import { GoogleUserInfo } from '../../types/auth.types';

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
}

export interface IOAuthService {
  generateAuthUrl(state?: string): string;
  exchangeCodeForTokens(code: string): Promise<OAuthTokens>;
  getUserInfo(accessToken: string): Promise<GoogleUserInfo>;
  validateState(receivedState: string, expectedState?: string): boolean;
}