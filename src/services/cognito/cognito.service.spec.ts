import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { CognitoService } from './cognito.service';
import {
  AdminDeleteUserCommand,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ForgotPasswordCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  AuthenticationError,
  CognitoServiceError,
  UserAlreadyExistsError,
  UserNotFoundError,
} from '../../errors/auth.errors';

vi.mock('@aws-sdk/client-cognito-identity-provider');

describe('CognitoService', () => {
  let cognitoService: CognitoService;
  let mockClient: CognitoIdentityProviderClient;
  let mockSend: Mock;

  const mockCognitoUser = {
    Username: 'test@example.com',
    Attributes: [
      { Name: 'email', Value: 'test@example.com' },
      { Name: 'given_name', Value: 'John' },
      { Name: 'family_name', Value: 'Doe' },
      { Name: 'email_verified', Value: 'true' },
    ],
    UserStatus: 'CONFIRMED',
    Enabled: true,
    UserCreateDate: new Date('2023-01-01'),
    UserLastModifiedDate: new Date('2023-01-02'),
  };

  beforeEach(() => {
    vi.clearAllMocks();

    mockSend = vi.fn();
    mockClient = {
      send: mockSend,
    } as any;

    (CognitoIdentityProviderClient as Mock).mockImplementation(() => mockClient);

    process.env.AWS_REGION = 'us-east-1';
    process.env.AWS_ACCESS_KEY_ID = 'test-access-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'test-secret-key';
    process.env.COGNITO_USER_POOL_ID = 'us-east-1_testpool';
    process.env.COGNITO_CLIENT_ID = 'test-client-id';
    process.env.COGNITO_CLIENT_SECRET = 'test-client-secret';

    cognitoService = new CognitoService();
  });

  describe('constructor', () => {
    it('should initialize with environment variables', () => {
      expect(cognitoService).toBeInstanceOf(CognitoService);
      expect(CognitoIdentityProviderClient).toHaveBeenCalledWith({
        region: 'us-east-1',
        credentials: {
          accessKeyId: 'test-access-key',
          secretAccessKey: 'test-secret-key',
        },
      });
    });

    it('should throw error when required environment variables are missing', () => {
      delete process.env.COGNITO_USER_POOL_ID;

      expect(() => new CognitoService()).toThrow(
        'Missing required Cognito configuration. Please check your environment variables.'
      );
    });

    it('should use default AWS region when not provided', () => {
      delete process.env.AWS_REGION;
      new CognitoService();

      expect(CognitoIdentityProviderClient).toHaveBeenCalledWith(
        expect.objectContaining({
          region: 'us-east-1',
        })
      );
    });
  });

  describe('createUser', () => {
    it('should create a new user successfully', async () => {
      // Mock getUserByEmail to throw UserNotFoundError (user doesn't exist)
      let callCount = 0;
      mockSend.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject({ name: 'UserNotFoundException' });
        } else if (callCount === 2) {
          return Promise.resolve({ User: mockCognitoUser });
        } else {
          return Promise.resolve({});
        }
      });

      const result = await cognitoService.createUser(
        'test@example.com',
        'TestPassword123!',
        'John',
        'Doe'
      );

      expect(mockSend).toHaveBeenCalledTimes(3);
      expect(result.email).toBe('test@example.com');
      expect(result.firstName).toBe('John');
      expect(result.lastName).toBe('Doe');
    });

    it('should throw UserAlreadyExistsError when user exists', async () => {
      // Mock getUserByEmail to return existing user
      mockSend.mockResolvedValue({
        Username: 'test@example.com',
        UserAttributes: mockCognitoUser.Attributes,
        UserStatus: 'CONFIRMED',
        Enabled: true,
        UserCreateDate: new Date('2023-01-01'),
        UserLastModifiedDate: new Date('2023-01-02'),
      });

      await expect(
        cognitoService.createUser('test@example.com', 'TestPassword123!', 'John', 'Doe')
      ).rejects.toThrow(UserAlreadyExistsError);
    });

    it('should handle UsernameExistsException from Cognito', async () => {
      let callCount = 0;
      mockSend.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject({ name: 'UserNotFoundException' });
        } else {
          return Promise.reject({ name: 'UsernameExistsException' });
        }
      });

      await expect(
        cognitoService.createUser('test@example.com', 'TestPassword123!', 'John', 'Doe')
      ).rejects.toThrow(UserAlreadyExistsError);
    });

    it('should handle missing user data in response', async () => {
      let callCount = 0;
      mockSend.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject({ name: 'UserNotFoundException' });
        } else {
          return Promise.resolve({ User: null });
        }
      });

      await expect(
        cognitoService.createUser('test@example.com', 'TestPassword123!', 'John', 'Doe')
      ).rejects.toThrow(CognitoServiceError);
    });

    it('should handle generic Cognito errors', async () => {
      let callCount = 0;
      mockSend.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject({ name: 'UserNotFoundException' });
        } else {
          return Promise.reject({ name: 'ServiceError', message: 'Service unavailable' });
        }
      });

      await expect(
        cognitoService.createUser('test@example.com', 'TestPassword123!', 'John', 'Doe')
      ).rejects.toThrow(CognitoServiceError);
    });
  });

  describe('authenticateUser', () => {
    it('should authenticate user successfully', async () => {
      const mockAuthResult = {
        AuthenticationResult: {
          AccessToken: 'access-token',
          RefreshToken: 'refresh-token',
          IdToken: 'id-token',
        },
      };

      mockSend.mockResolvedValue(mockAuthResult);

      const result = await cognitoService.authenticateUser('test@example.com', 'password');

      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBe('refresh-token');
      expect(result.idToken).toBe('id-token');
    });

    it('should throw error when no AuthenticationResult', async () => {
      mockSend.mockResolvedValue({});

      await expect(
        cognitoService.authenticateUser('test@example.com', 'password')
      ).rejects.toThrow('Authentication failed - no tokens returned');
    });

    it('should throw error when tokens are missing', async () => {
      mockSend.mockResolvedValue({
        AuthenticationResult: {
          AccessToken: null,
          RefreshToken: 'refresh-token',
          IdToken: 'id-token',
        },
      });

      await expect(
        cognitoService.authenticateUser('test@example.com', 'password')
      ).rejects.toThrow('Authentication failed - incomplete token response');
    });

    it('should handle NotAuthorizedException', async () => {
      mockSend.mockRejectedValue({ name: 'NotAuthorizedException' });

      await expect(
        cognitoService.authenticateUser('test@example.com', 'wrong-password')
      ).rejects.toThrow(AuthenticationError);
    });

    it('should handle UserNotConfirmedException', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotConfirmedException' });

      await expect(
        cognitoService.authenticateUser('test@example.com', 'password')
      ).rejects.toThrow(AuthenticationError);
    });

    it('should handle UserNotFoundException', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotFoundException' });

      await expect(
        cognitoService.authenticateUser('nonexistent@example.com', 'password')
      ).rejects.toThrow(UserNotFoundError);
    });

    it('should handle generic Cognito errors', async () => {
      mockSend.mockRejectedValue({ name: 'ServiceError', message: 'Service error' });

      await expect(
        cognitoService.authenticateUser('test@example.com', 'password')
      ).rejects.toThrow(CognitoServiceError);
    });
  });

  describe('getUserByEmail', () => {
    it('should get user successfully', async () => {
      mockSend.mockResolvedValue({
        Username: 'test@example.com',
        UserAttributes: mockCognitoUser.Attributes,
        UserStatus: 'CONFIRMED',
        Enabled: true,
        UserCreateDate: new Date('2023-01-01'),
        UserLastModifiedDate: new Date('2023-01-02'),
      });

      const result = await cognitoService.getUserByEmail('test@example.com');

      expect(result.email).toBe('test@example.com');
      expect(result.firstName).toBe('John');
      expect(result.lastName).toBe('Doe');
      expect(result.provider).toBe('cognito');
    });

    it('should throw UserNotFoundError when user not found', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotFoundException' });

      await expect(cognitoService.getUserByEmail('nonexistent@example.com')).rejects.toThrow(
        UserNotFoundError
      );
    });

    it('should throw UserNotFoundError when no attributes', async () => {
      mockSend.mockResolvedValue({
        Username: 'test@example.com',
        UserAttributes: null,
      });

      await expect(cognitoService.getUserByEmail('test@example.com')).rejects.toThrow(
        'User not found'
      );
    });

    it('should handle generic Cognito errors', async () => {
      mockSend.mockRejectedValue({ name: 'ServiceError', message: 'Service error' });

      await expect(cognitoService.getUserByEmail('test@example.com')).rejects.toThrow(
        CognitoServiceError
      );
    });
  });

  describe('initiatePasswordReset', () => {
    it('should initiate password reset successfully', async () => {
      mockSend.mockResolvedValue({});

      await expect(cognitoService.initiatePasswordReset('test@example.com')).resolves.toBeUndefined();
      expect(mockSend).toHaveBeenCalledWith(expect.any(ForgotPasswordCommand));
    });

    it('should handle UserNotFoundException', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotFoundException' });

      await expect(cognitoService.initiatePasswordReset('nonexistent@example.com')).rejects.toThrow(
        UserNotFoundError
      );
    });

    it('should handle generic Cognito errors', async () => {
      mockSend.mockRejectedValue({ name: 'ServiceError', message: 'Service error' });

      await expect(cognitoService.initiatePasswordReset('test@example.com')).rejects.toThrow(
        CognitoServiceError
      );
    });
  });

  describe('confirmPasswordReset', () => {
    it('should confirm password reset successfully', async () => {
      mockSend.mockResolvedValue({});

      await expect(
        cognitoService.confirmPasswordReset('test@example.com', '123456', 'NewPassword123!')
      ).resolves.toBeUndefined();
      expect(mockSend).toHaveBeenCalledWith(expect.any(ConfirmForgotPasswordCommand));
    });

    it('should handle ExpiredCodeException', async () => {
      mockSend.mockRejectedValue({ name: 'ExpiredCodeException' });

      await expect(
        cognitoService.confirmPasswordReset('test@example.com', '123456', 'NewPassword123!')
      ).rejects.toThrow(AuthenticationError);
    });

    it('should handle CodeMismatchException', async () => {
      mockSend.mockRejectedValue({ name: 'CodeMismatchException' });

      await expect(
        cognitoService.confirmPasswordReset('test@example.com', 'wrong', 'NewPassword123!')
      ).rejects.toThrow(AuthenticationError);
    });

    it('should handle UserNotFoundException', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotFoundException' });

      await expect(
        cognitoService.confirmPasswordReset('nonexistent@example.com', '123456', 'NewPassword123!')
      ).rejects.toThrow(UserNotFoundError);
    });

    it('should handle generic Cognito errors', async () => {
      mockSend.mockRejectedValue({ name: 'ServiceError', message: 'Service error' });

      await expect(
        cognitoService.confirmPasswordReset('test@example.com', '123456', 'NewPassword123!')
      ).rejects.toThrow(CognitoServiceError);
    });
  });

  describe('deleteUser', () => {
    it('should delete user successfully', async () => {
      mockSend.mockResolvedValue({});

      await expect(cognitoService.deleteUser('test@example.com')).resolves.toBeUndefined();
      expect(mockSend).toHaveBeenCalledWith(expect.any(AdminDeleteUserCommand));
    });

    it('should handle UserNotFoundException', async () => {
      mockSend.mockRejectedValue({ name: 'UserNotFoundException' });

      await expect(cognitoService.deleteUser('nonexistent@example.com')).rejects.toThrow(
        UserNotFoundError
      );
    });

    it('should handle generic Cognito errors', async () => {
      mockSend.mockRejectedValue({ name: 'ServiceError', message: 'Service error' });

      await expect(cognitoService.deleteUser('test@example.com')).rejects.toThrow(
        CognitoServiceError
      );
    });
  });

  describe('calculateSecretHash', () => {
    it('should calculate secret hash correctly', () => {
      const service = cognitoService as any;
      const hash = service.calculateSecretHash('test@example.com');
      
      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });
  });

  describe('mapCognitoUserToProfile', () => {
    it('should map Cognito user to UserProfile correctly', () => {
      const service = cognitoService as any;
      const profile = service.mapCognitoUserToProfile(mockCognitoUser);

      expect(profile.id).toBe('test@example.com');
      expect(profile.email).toBe('test@example.com');
      expect(profile.firstName).toBe('John');
      expect(profile.lastName).toBe('Doe');
      expect(profile.provider).toBe('cognito');
      expect(profile.emailVerified).toBe(true);
      expect(profile.createdAt).toBe('2023-01-01T00:00:00.000Z');
      expect(profile.updatedAt).toBe('2023-01-02T00:00:00.000Z');
    });

    it('should handle missing attributes gracefully', () => {
      const service = cognitoService as any;
      const userWithMissingAttrs = {
        ...mockCognitoUser,
        Attributes: [
          { Name: 'email', Value: 'test@example.com' },
        ],
      };

      const profile = service.mapCognitoUserToProfile(userWithMissingAttrs);

      expect(profile.firstName).toBe('');
      expect(profile.lastName).toBe('');
      expect(profile.emailVerified).toBe(false);
    });
  });
});