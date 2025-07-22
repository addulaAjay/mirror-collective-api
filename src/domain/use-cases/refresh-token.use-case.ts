import { IAuthRepository } from '../repositories';
import { AuthResponse } from '../../types/auth.types';

export interface RefreshTokenRequest {
  refreshToken: string;
}

export class RefreshTokenUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: RefreshTokenRequest): Promise<AuthResponse> {
    // Refresh tokens with Cognito
    const authResult = await this.authRepository.refreshToken(request.refreshToken);

    // Since we're using API Gateway Cognito authorizers, we don't need to decode JWTs
    // However, we still need user information for the response
    // Note: In a real-world scenario with API Gateway auth, this endpoint might not be needed
    // as clients would refresh tokens directly with Cognito and get user info from protected endpoints

    // For now, we'll return a minimal response since the main authentication will happen at API Gateway
    return {
      success: true,
      data: {
        user: {
          id: '', // Will be populated by API Gateway context in protected endpoints
          email: '', // Will be populated by API Gateway context in protected endpoints
          fullName: '', // Will be populated by API Gateway context in protected endpoints
          isVerified: true, // Assume verified since refresh token is valid
        },
        tokens: {
          accessToken: authResult.accessToken,
          refreshToken: authResult.refreshToken,
        },
      },
      message:
        'Token refreshed successfully. User info will be available through protected endpoints.',
    };
  }
}
