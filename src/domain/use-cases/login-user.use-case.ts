import { AuthenticateUserRequest, IAuthRepository } from '../repositories';
import { AuthResponse } from '../../types/auth.types';

export interface LoginUserRequest extends AuthenticateUserRequest {}

export class LoginUserUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: LoginUserRequest): Promise<AuthResponse> {
    // Authenticate with Cognito and get tokens
    const authResult = await this.authRepository.authenticateUser(request);

    // Get user profile
    const user = await this.authRepository.getUserByEmail(request.email);

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
          accessToken: authResult.accessToken, // Use Cognito access token
          refreshToken: authResult.refreshToken, // Use Cognito refresh token
        },
      },
      message: 'Login successful',
    };
  }
}
