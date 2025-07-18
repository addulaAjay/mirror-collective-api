import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  AuthFlowType,
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
import { CognitoUser, UserProfile } from '../../types/auth.types';

/**
 * AWS Cognito service for user management and authentication
 */
export class CognitoService {
  private client: CognitoIdentityProviderClient;
  private userPoolId: string;
  private clientId: string;
  private clientSecret: string;

  constructor() {
    this.client = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
      },
    });

    this.userPoolId = process.env.COGNITO_USER_POOL_ID!;
    this.clientId = process.env.COGNITO_CLIENT_ID!;
    this.clientSecret = process.env.COGNITO_CLIENT_SECRET!;

    if (!this.userPoolId || !this.clientId || !this.clientSecret) {
      throw new Error(
        'Missing required Cognito configuration. Please check your environment variables.'
      );
    }
  }

  /**
   * Create a new user in Cognito User Pool
   */
  async createUser(
    email: string,
    password: string,
    firstName: string,
    lastName: string
  ): Promise<UserProfile> {
    try {
      // Check if user already exists
      await this.getUserByEmail(email);
      throw new UserAlreadyExistsError('A user with this email already exists');
    } catch (error) {
      if (error instanceof UserNotFoundError) {
        // User doesn't exist, proceed with creation
      } else {
        throw error;
      }
    }

    try {
      const command = new AdminCreateUserCommand({
        UserPoolId: this.userPoolId,
        Username: email,
        UserAttributes: [
          {
            Name: 'email',
            Value: email,
          },
          {
            Name: 'given_name',
            Value: firstName,
          },
          {
            Name: 'family_name',
            Value: lastName,
          },
          {
            Name: 'email_verified',
            Value: 'false',
          },
        ],
        TemporaryPassword: password,
        MessageAction: 'SUPPRESS', // Don't send welcome email
      });

      const response = await this.client.send(command);

      // Set permanent password
      const setPasswordCommand = new AdminSetUserPasswordCommand({
        UserPoolId: this.userPoolId,
        Username: email,
        Password: password,
        Permanent: true,
      });

      await this.client.send(setPasswordCommand);

      if (!response.User) {
        throw new CognitoServiceError('Failed to create user - no user data returned');
      }

      return this.mapCognitoUserToProfile(response.User as any);
    } catch (error: any) {
      if (error.name === 'UsernameExistsException') {
        throw new UserAlreadyExistsError('A user with this email already exists');
      }

      console.error('Error creating user in Cognito:', error);
      throw new CognitoServiceError(`Failed to create user: ${error.message}`, error.name);
    }
  }

  /**
   * Authenticate user with email and password
   */
  async authenticateUser(
    email: string,
    password: string
  ): Promise<{ accessToken: string; refreshToken: string; idToken: string }> {
    try {
      const command = new AdminInitiateAuthCommand({
        UserPoolId: this.userPoolId,
        ClientId: this.clientId,
        AuthFlow: AuthFlowType.ADMIN_NO_SRP_AUTH,
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
          SECRET_HASH: this.calculateSecretHash(email),
        },
      });

      const response = await this.client.send(command);

      if (!response.AuthenticationResult) {
        throw new AuthenticationError('Authentication failed - no tokens returned');
      }

      const { AccessToken, RefreshToken, IdToken } = response.AuthenticationResult;

      if (!AccessToken || !RefreshToken || !IdToken) {
        throw new AuthenticationError('Authentication failed - incomplete token response');
      }

      return {
        accessToken: AccessToken,
        refreshToken: RefreshToken,
        idToken: IdToken,
      };
    } catch (error: any) {
      console.error('Error authenticating user:', error);

      if (error.name === 'NotAuthorizedException') {
        throw new AuthenticationError('Invalid email or password');
      }

      if (error.name === 'UserNotConfirmedException') {
        throw new AuthenticationError('Please verify your email address before logging in');
      }

      if (error.name === 'UserNotFoundException') {
        throw new UserNotFoundError('User not found');
      }

      throw new CognitoServiceError(`Authentication failed: ${error.message}`, error.name);
    }
  }

  /**
   * Get user by email
   */
  async getUserByEmail(email: string): Promise<UserProfile> {
    try {
      const command = new AdminGetUserCommand({
        UserPoolId: this.userPoolId,
        Username: email,
      });

      const response = await this.client.send(command);

      if (!response.UserAttributes) {
        throw new UserNotFoundError('User not found');
      }

      return this.mapCognitoUserToProfile({
        Username: response.Username,
        Attributes: response.UserAttributes,
        UserStatus: response.UserStatus,
        Enabled: response.Enabled,
        UserCreateDate: response.UserCreateDate,
        UserLastModifiedDate: response.UserLastModifiedDate,
      } as CognitoUser);
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        throw new UserNotFoundError('User not found');
      }

      console.error('Error getting user by email:', error);
      throw new CognitoServiceError(`Failed to get user: ${error.message}`, error.name);
    }
  }

  /**
   * Initiate forgot password flow
   */
  async initiatePasswordReset(email: string): Promise<void> {
    try {
      const command = new ForgotPasswordCommand({
        ClientId: this.clientId,
        Username: email,
        SecretHash: this.calculateSecretHash(email),
      });

      await this.client.send(command);
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        throw new UserNotFoundError('User not found');
      }

      console.error('Error initiating password reset:', error);
      throw new CognitoServiceError(
        `Failed to initiate password reset: ${error.message}`,
        error.name
      );
    }
  }

  /**
   * Confirm password reset with code
   */
  async confirmPasswordReset(email: string, code: string, newPassword: string): Promise<void> {
    try {
      const command = new ConfirmForgotPasswordCommand({
        ClientId: this.clientId,
        Username: email,
        ConfirmationCode: code,
        Password: newPassword,
        SecretHash: this.calculateSecretHash(email),
      });

      await this.client.send(command);
    } catch (error: any) {
      if (error.name === 'ExpiredCodeException') {
        throw new AuthenticationError('Reset code has expired');
      }

      if (error.name === 'CodeMismatchException') {
        throw new AuthenticationError('Invalid reset code');
      }

      if (error.name === 'UserNotFoundException') {
        throw new UserNotFoundError('User not found');
      }

      console.error('Error confirming password reset:', error);
      throw new CognitoServiceError(`Failed to reset password: ${error.message}`, error.name);
    }
  }

  /**
   * Delete user from Cognito User Pool
   */
  async deleteUser(email: string): Promise<void> {
    try {
      const command = new AdminDeleteUserCommand({
        UserPoolId: this.userPoolId,
        Username: email,
      });

      await this.client.send(command);
    } catch (error: any) {
      if (error.name === 'UserNotFoundException') {
        throw new UserNotFoundError('User not found');
      }

      console.error('Error deleting user:', error);
      throw new CognitoServiceError(`Failed to delete user: ${error.message}`, error.name);
    }
  }

  /**
   * Calculate secret hash for Cognito operations
   */
  private calculateSecretHash(username: string): string {
    const crypto = require('crypto');
    const message = username + this.clientId;
    return crypto.createHmac('SHA256', this.clientSecret).update(message).digest('base64');
  }

  /**
   * Map Cognito user data to UserProfile
   */
  private mapCognitoUserToProfile(cognitoUser: CognitoUser): UserProfile {
    const getAttribute = (name: string): string => {
      const attr = cognitoUser.Attributes.find((attr) => attr.Name === name);
      return attr?.Value || '';
    };

    return {
      id: cognitoUser.Username,
      email: getAttribute('email'),
      firstName: getAttribute('given_name'),
      lastName: getAttribute('family_name'),
      provider: 'cognito',
      emailVerified: getAttribute('email_verified') === 'true',
      createdAt: cognitoUser.UserCreateDate.toISOString(),
      updatedAt: cognitoUser.UserLastModifiedDate.toISOString(),
    };
  }
}
