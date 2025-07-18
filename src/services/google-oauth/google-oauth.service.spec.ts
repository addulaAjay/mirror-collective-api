import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { GoogleOAuthService } from './google-oauth.service';
import { google } from 'googleapis';
import { GoogleOAuthError } from '../../errors/auth.errors';

vi.mock('googleapis');

describe('GoogleOAuthService', () => {
  let googleOAuthService: GoogleOAuthService;
  let mockOAuth2Client: any;
  let mockOAuth2Api: any;

  beforeEach(() => {
    vi.clearAllMocks();

    mockOAuth2Client = {
      generateAuthUrl: vi.fn(),
      getToken: vi.fn(),
      setCredentials: vi.fn(),
      verifyIdToken: vi.fn(),
      refreshAccessToken: vi.fn(),
      revokeToken: vi.fn(),
    };

    mockOAuth2Api = {
      userinfo: {
        get: vi.fn(),
      },
    };

    (google.auth.OAuth2 as any).mockImplementation(() => mockOAuth2Client);
    (google.oauth2 as Mock).mockReturnValue(mockOAuth2Api);

    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/auth/google/callback';

    googleOAuthService = new GoogleOAuthService();
  });

  describe('constructor', () => {
    it('should initialize with environment variables', () => {
      expect(googleOAuthService).toBeInstanceOf(GoogleOAuthService);
      expect(google.auth.OAuth2).toHaveBeenCalledWith(
        'test-client-id',
        'test-client-secret',
        'http://localhost:3000/auth/google/callback'
      );
    });

    it('should throw error when required environment variables are missing', () => {
      delete process.env.GOOGLE_CLIENT_ID;

      expect(() => new GoogleOAuthService()).toThrow(
        'Missing required Google OAuth configuration. Please check your environment variables.'
      );
    });
  });

  describe('generateAuthUrl', () => {
    it('should generate auth URL with default state', () => {
      const mockUrl = 'https://accounts.google.com/oauth/authorize?...';
      mockOAuth2Client.generateAuthUrl.mockReturnValue(mockUrl);

      const result = googleOAuthService.generateAuthUrl();

      expect(mockOAuth2Client.generateAuthUrl).toHaveBeenCalledWith({
        access_type: 'offline',
        scope: [
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
        ],
        include_granted_scopes: true,
        state: 'default_state',
        prompt: 'consent',
      });
      expect(result).toBe(mockUrl);
    });

    it('should generate auth URL with custom state', () => {
      const mockUrl = 'https://accounts.google.com/oauth/authorize?...';
      mockOAuth2Client.generateAuthUrl.mockReturnValue(mockUrl);

      const result = googleOAuthService.generateAuthUrl('custom-state');

      expect(mockOAuth2Client.generateAuthUrl).toHaveBeenCalledWith(
        expect.objectContaining({
          state: 'custom-state',
        })
      );
      expect(result).toBe(mockUrl);
    });
  });

  describe('exchangeCodeForTokens', () => {
    it('should exchange code for tokens successfully', async () => {
      const mockTokens = {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        id_token: 'id-token',
      };
      mockOAuth2Client.getToken.mockResolvedValue({ tokens: mockTokens });

      const result = await googleOAuthService.exchangeCodeForTokens('auth-code');

      expect(mockOAuth2Client.getToken).toHaveBeenCalledWith('auth-code');
      expect(result).toEqual({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        idToken: 'id-token',
      });
    });

    it('should handle missing access token', async () => {
      mockOAuth2Client.getToken.mockResolvedValue({
        tokens: { refresh_token: 'refresh-token' },
      });

      await expect(googleOAuthService.exchangeCodeForTokens('auth-code')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle Google OAuth errors', async () => {
      mockOAuth2Client.getToken.mockRejectedValue(new Error('Invalid code'));

      await expect(googleOAuthService.exchangeCodeForTokens('invalid-code')).rejects.toThrow(
        GoogleOAuthError
      );
    });
  });

  describe('getUserInfo', () => {
    it('should get user info successfully', async () => {
      const mockUserData = {
        id: 'google-user-id',
        email: 'user@gmail.com',
        verified_email: true,
        given_name: 'John',
        family_name: 'Doe',
        picture: 'https://example.com/picture.jpg',
      };
      mockOAuth2Api.userinfo.get.mockResolvedValue({ data: mockUserData });

      const result = await googleOAuthService.getUserInfo('access-token');

      expect(mockOAuth2Client.setCredentials).toHaveBeenCalledWith({
        access_token: 'access-token',
      });
      expect(google.oauth2).toHaveBeenCalledWith({ version: 'v2', auth: mockOAuth2Client });
      expect(result).toEqual(mockUserData);
    });

    it('should handle missing user data', async () => {
      mockOAuth2Api.userinfo.get.mockResolvedValue({ data: null });

      await expect(googleOAuthService.getUserInfo('access-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle missing email in user data', async () => {
      mockOAuth2Api.userinfo.get.mockResolvedValue({
        data: { id: 'user-id', given_name: 'John' },
      });

      await expect(googleOAuthService.getUserInfo('access-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle Google API errors', async () => {
      mockOAuth2Api.userinfo.get.mockRejectedValue(new Error('API error'));

      await expect(googleOAuthService.getUserInfo('access-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle missing optional fields gracefully', async () => {
      const mockUserData = {
        id: 'google-user-id',
        email: 'user@gmail.com',
      };
      mockOAuth2Api.userinfo.get.mockResolvedValue({ data: mockUserData });

      const result = await googleOAuthService.getUserInfo('access-token');

      expect(result).toEqual({
        id: 'google-user-id',
        email: 'user@gmail.com',
        verified_email: false,
        given_name: '',
        family_name: '',
        picture: undefined,
      });
    });
  });

  describe('verifyIdToken', () => {
    it('should verify ID token successfully', async () => {
      const mockPayload = {
        sub: 'google-user-id',
        email: 'user@gmail.com',
        email_verified: true,
        given_name: 'John',
        family_name: 'Doe',
        picture: 'https://example.com/picture.jpg',
      };
      const mockTicket = {
        getPayload: vi.fn().mockReturnValue(mockPayload),
      };
      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      const result = await googleOAuthService.verifyIdToken('id-token');

      expect(mockOAuth2Client.verifyIdToken).toHaveBeenCalledWith({
        idToken: 'id-token',
        audience: 'test-client-id',
      });
      expect(result).toEqual({
        id: 'google-user-id',
        email: 'user@gmail.com',
        verified_email: true,
        given_name: 'John',
        family_name: 'Doe',
        picture: 'https://example.com/picture.jpg',
      });
    });

    it('should handle missing payload', async () => {
      const mockTicket = {
        getPayload: vi.fn().mockReturnValue(null),
      };
      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      await expect(googleOAuthService.verifyIdToken('id-token')).rejects.toThrow(GoogleOAuthError);
    });

    it('should handle missing email in payload', async () => {
      const mockTicket = {
        getPayload: vi.fn().mockReturnValue({ sub: 'user-id' }),
      };
      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      await expect(googleOAuthService.verifyIdToken('id-token')).rejects.toThrow(GoogleOAuthError);
    });

    it('should handle verification errors', async () => {
      mockOAuth2Client.verifyIdToken.mockRejectedValue(new Error('Invalid token'));

      await expect(googleOAuthService.verifyIdToken('invalid-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle missing optional fields gracefully', async () => {
      const mockPayload = {
        sub: 'google-user-id',
        email: 'user@gmail.com',
      };
      const mockTicket = {
        getPayload: vi.fn().mockReturnValue(mockPayload),
      };
      mockOAuth2Client.verifyIdToken.mockResolvedValue(mockTicket);

      const result = await googleOAuthService.verifyIdToken('id-token');

      expect(result).toEqual({
        id: 'google-user-id',
        email: 'user@gmail.com',
        verified_email: false,
        given_name: '',
        family_name: '',
        picture: undefined,
      });
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh access token successfully', async () => {
      const mockCredentials = {
        access_token: 'new-access-token',
        expiry_date: Date.now() + 3600 * 1000, // 1 hour from now
      };
      mockOAuth2Client.refreshAccessToken.mockResolvedValue({
        credentials: mockCredentials,
      });

      const result = await googleOAuthService.refreshAccessToken('refresh-token');

      expect(mockOAuth2Client.setCredentials).toHaveBeenCalledWith({
        refresh_token: 'refresh-token',
      });
      expect(result.accessToken).toBe('new-access-token');
      expect(result.expiresIn).toBeGreaterThan(0);
    });

    it('should handle missing access token in refresh response', async () => {
      mockOAuth2Client.refreshAccessToken.mockResolvedValue({
        credentials: { refresh_token: 'refresh-token' },
      });

      await expect(googleOAuthService.refreshAccessToken('refresh-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle refresh errors', async () => {
      mockOAuth2Client.refreshAccessToken.mockRejectedValue(new Error('Invalid refresh token'));

      await expect(googleOAuthService.refreshAccessToken('invalid-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });

    it('should handle missing expiry date', async () => {
      const mockCredentials = {
        access_token: 'new-access-token',
      };
      mockOAuth2Client.refreshAccessToken.mockResolvedValue({
        credentials: mockCredentials,
      });

      const result = await googleOAuthService.refreshAccessToken('refresh-token');

      expect(result.accessToken).toBe('new-access-token');
      expect(result.expiresIn).toBeUndefined();
    });
  });

  describe('revokeTokens', () => {
    it('should revoke tokens successfully', async () => {
      mockOAuth2Client.revokeToken.mockResolvedValue({});

      await expect(googleOAuthService.revokeTokens('access-token')).resolves.toBeUndefined();
      expect(mockOAuth2Client.revokeToken).toHaveBeenCalledWith('access-token');
    });

    it('should handle revoke errors', async () => {
      mockOAuth2Client.revokeToken.mockRejectedValue(new Error('Revoke failed'));

      await expect(googleOAuthService.revokeTokens('access-token')).rejects.toThrow(
        GoogleOAuthError
      );
    });
  });

  describe('validateState', () => {
    it('should validate state with default state when no expected state', () => {
      const result = googleOAuthService.validateState('default_state');
      expect(result).toBe(true);
    });

    it('should invalidate wrong default state', () => {
      const result = googleOAuthService.validateState('wrong-state');
      expect(result).toBe(false);
    });

    it('should validate state with expected state', () => {
      const result = googleOAuthService.validateState('custom-state', 'custom-state');
      expect(result).toBe(true);
    });

    it('should invalidate wrong expected state', () => {
      const result = googleOAuthService.validateState('wrong-state', 'expected-state');
      expect(result).toBe(false);
    });
  });
});