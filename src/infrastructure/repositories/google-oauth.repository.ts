import { IOAuthService, OAuthTokens } from '../../domain/repositories/oauth.repository';
import { GoogleUserInfo } from '../../types/auth.types';
import { GoogleOAuthService } from '../../services';

export class GoogleOAuthRepository implements IOAuthService {
  private googleOAuthService: GoogleOAuthService;

  constructor() {
    this.googleOAuthService = new GoogleOAuthService();
  }

  generateAuthUrl(state?: string): string {
    return this.googleOAuthService.generateAuthUrl(state);
  }

  async exchangeCodeForTokens(code: string): Promise<OAuthTokens> {
    return this.googleOAuthService.exchangeCodeForTokens(code);
  }

  async getUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    return this.googleOAuthService.getUserInfo(accessToken);
  }

  validateState(receivedState: string, expectedState?: string): boolean {
    return this.googleOAuthService.validateState(receivedState, expectedState);
  }
}
