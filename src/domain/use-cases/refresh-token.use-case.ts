import jwt from 'jsonwebtoken';
import { IAuthRepository } from '../repositories';
import { AuthResponse, CognitoJwtPayload } from '../../types/auth.types';

export interface RefreshTokenRequest {
  refreshToken: string;
}

export class RefreshTokenUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: RefreshTokenRequest): Promise<AuthResponse> {
    // Refresh tokens with Cognito
    const authResult = await this.authRepository.refreshToken(request.refreshToken);

    // Decode the new access token to get user information
    const decoded = jwt.decode(authResult.accessToken) as CognitoJwtPayload;

    if (!decoded || !decoded.email) {
      throw new Error('Invalid access token received from Cognito');
    }

    // Fetch full user profile using the email from token
    const user = await this.authRepository.getUserByEmail(decoded.email);

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
          accessToken: authResult.accessToken,
          refreshToken: authResult.refreshToken,
        },
      },
      message: 'Token refreshed successfully',
    };
  }
}
