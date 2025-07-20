import { IAuthRepository, IEmailService, IOAuthService, ITokenService } from '../repositories';
import { UserProfile } from '../../types/auth.types';
import { UserNotFoundError } from '../../errors/auth.errors';

export interface GoogleOAuthCallbackRequest {
  code: string;
  state?: string;
}

export interface GoogleOAuthCallbackResponse {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  user?: UserProfile;
}

export class GoogleOAuthCallbackUseCase {
  constructor(
    private oauthService: IOAuthService,
    private authRepository: IAuthRepository,
    private tokenService: ITokenService,
    private emailService: IEmailService
  ) {}

  async execute(request: GoogleOAuthCallbackRequest): Promise<GoogleOAuthCallbackResponse> {
    // Validate state if provided
    if (request.state && !this.oauthService.validateState(request.state)) {
      throw new Error('Invalid OAuth state parameter');
    }

    // Exchange code for tokens
    const googleTokens = await this.oauthService.exchangeCodeForTokens(request.code);

    // Get user info from Google
    const googleUser = await this.oauthService.getUserInfo(googleTokens.accessToken);

    // Check if user exists
    let user: UserProfile;
    try {
      user = await this.authRepository.getUserByEmail(googleUser.email);
    } catch (error) {
      if (error instanceof UserNotFoundError) {
        // Create new user
        const fullName = `${googleUser.given_name} ${googleUser.family_name}`.trim();
        user = await this.authRepository.createUser({
          email: googleUser.email,
          password: this.generateRandomPassword(),
          fullName,
        });

        // Send welcome email (non-blocking)
        this.emailService.sendWelcomeEmail(user.email, user.firstName).catch((error) => {
          console.error('Failed to send welcome email:', error);
        });
      } else {
        throw error;
      }
    }

    // Update user profile to indicate Google provider
    const updatedUser: UserProfile = {
      ...user,
      provider: 'google',
      emailVerified: googleUser.verified_email,
    };

    // Generate our own JWT tokens
    const { accessToken, refreshToken } = this.tokenService.generateTokenPair(updatedUser);

    return {
      success: true,
      accessToken,
      refreshToken,
      user: updatedUser,
    };
  }

  private generateRandomPassword(length: number = 16): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';

    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }

    return password;
  }
}
