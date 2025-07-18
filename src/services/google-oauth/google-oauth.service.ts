import { google } from 'googleapis';
import { GoogleOAuthError } from '../../errors/auth.errors';
import { GoogleUserInfo } from '../../types/auth.types';

/**
 * Google OAuth service for handling Google authentication
 */
export class GoogleOAuthService {
  private oauth2Client: any;
  private clientId: string;
  private clientSecret: string;
  private redirectUri: string;

  constructor() {
    this.clientId = process.env.GOOGLE_CLIENT_ID!;
    this.clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
    this.redirectUri = process.env.GOOGLE_REDIRECT_URI!;

    if (!this.clientId || !this.clientSecret || !this.redirectUri) {
      throw new Error(
        'Missing required Google OAuth configuration. Please check your environment variables.'
      );
    }

    this.oauth2Client = new google.auth.OAuth2(this.clientId, this.clientSecret, this.redirectUri);
  }

  /**
   * Generate Google OAuth authorization URL
   */
  generateAuthUrl(state?: string): string {
    const scopes = [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ];

    const authUrl = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      include_granted_scopes: true,
      state: state || 'default_state',
      prompt: 'consent',
    });

    return authUrl;
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(
    code: string
  ): Promise<{ accessToken: string; refreshToken?: string; idToken?: string }> {
    try {
      const { tokens } = await this.oauth2Client.getToken(code);

      if (!tokens.access_token) {
        throw new GoogleOAuthError('No access token received from Google');
      }

      return {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        idToken: tokens.id_token,
      };
    } catch (error: any) {
      console.error('Error exchanging Google OAuth code for tokens:', error);
      throw new GoogleOAuthError(`Failed to exchange code for tokens: ${error.message}`);
    }
  }

  /**
   * Get user information from Google using access token
   */
  async getUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    try {
      this.oauth2Client.setCredentials({ access_token: accessToken });

      const oauth2 = google.oauth2({ version: 'v2', auth: this.oauth2Client });
      const response = await oauth2.userinfo.get();

      if (!response.data || !response.data.email) {
        throw new GoogleOAuthError('Invalid user data received from Google');
      }

      const userData = response.data;

      return {
        id: userData.id!,
        email: userData.email!,
        verified_email: userData.verified_email || false,
        given_name: userData.given_name || '',
        family_name: userData.family_name || '',
        picture: userData.picture || undefined,
      };
    } catch (error: any) {
      console.error('Error getting Google user info:', error);
      throw new GoogleOAuthError(`Failed to get user information: ${error.message}`);
    }
  }

  /**
   * Verify Google ID token
   */
  async verifyIdToken(idToken: string): Promise<GoogleUserInfo> {
    try {
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken,
        audience: this.clientId,
      });

      const payload = ticket.getPayload();

      if (!payload || !payload.email) {
        throw new GoogleOAuthError('Invalid ID token payload');
      }

      return {
        id: payload.sub!,
        email: payload.email!,
        verified_email: payload.email_verified || false,
        given_name: payload.given_name || '',
        family_name: payload.family_name || '',
        picture: payload.picture || undefined,
      };
    } catch (error: any) {
      console.error('Error verifying Google ID token:', error);
      throw new GoogleOAuthError(`Failed to verify ID token: ${error.message}`);
    }
  }

  /**
   * Refresh Google access token
   */
  async refreshAccessToken(
    refreshToken: string
  ): Promise<{ accessToken: string; expiresIn?: number }> {
    try {
      this.oauth2Client.setCredentials({
        refresh_token: refreshToken,
      });

      const { credentials } = await this.oauth2Client.refreshAccessToken();

      if (!credentials.access_token) {
        throw new GoogleOAuthError('No access token received during refresh');
      }

      return {
        accessToken: credentials.access_token,
        expiresIn: credentials.expiry_date
          ? Math.floor((credentials.expiry_date - Date.now()) / 1000)
          : undefined,
      };
    } catch (error: any) {
      console.error('Error refreshing Google access token:', error);
      throw new GoogleOAuthError(`Failed to refresh access token: ${error.message}`);
    }
  }

  /**
   * Revoke Google tokens
   */
  async revokeTokens(accessToken: string): Promise<void> {
    try {
      await this.oauth2Client.revokeToken(accessToken);
    } catch (error: any) {
      console.error('Error revoking Google tokens:', error);
      throw new GoogleOAuthError(`Failed to revoke tokens: ${error.message}`);
    }
  }

  /**
   * Validate Google OAuth state parameter
   */
  validateState(receivedState: string, expectedState?: string): boolean {
    if (!expectedState) {
      return receivedState === 'default_state';
    }
    return receivedState === expectedState;
  }
}
