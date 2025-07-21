import { IAuthRepository, ITokenService } from '../repositories';
import { AuthResponse } from '../../types/auth.types';

export interface RefreshTokenRequest {
  refreshToken: string;
}

export class RefreshTokenUseCase {
  constructor(
    private tokenService: ITokenService,
    private authRepository: IAuthRepository
  ) {}

  async execute(request: RefreshTokenRequest): Promise<AuthResponse> {
    // Verify refresh token
    const decoded = this.tokenService.verifyRefreshToken(request.refreshToken);

    // Get current user data
    const user = await this.authRepository.getUserByEmail(decoded.email);

    // Generate new access token
    const { accessToken } = this.tokenService.refreshAccessToken(request.refreshToken, user);

    return {
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          fullName: `${user.firstName} ${user.lastName}`,
          isVerified: user.emailVerified,
        },
        tokens: {
          accessToken,
          refreshToken: request.refreshToken, // Keep the same refresh token
        },
      },
      message: 'Token refreshed successfully',
    };
  }
}
