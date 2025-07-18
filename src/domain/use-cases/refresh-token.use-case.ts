import { IAuthRepository, ITokenService } from '../repositories';
import { UserProfile } from '../../types/auth.types';

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  user?: UserProfile;
}

export class RefreshTokenUseCase {
  constructor(
    private tokenService: ITokenService,
    private authRepository: IAuthRepository
  ) {}

  async execute(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Verify refresh token
    const decoded = this.tokenService.verifyRefreshToken(request.refreshToken);

    // Get current user data
    const user = await this.authRepository.getUserByEmail(decoded.email);

    // Generate new access token
    const { accessToken } = this.tokenService.refreshAccessToken(request.refreshToken, user);

    return {
      success: true,
      accessToken,
      refreshToken: request.refreshToken, // Keep the same refresh token
      user,
    };
  }
}