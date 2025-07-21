import { AuthenticateUserRequest, IAuthRepository, ITokenService } from '../repositories';
import { AuthResponse } from '../../types/auth.types';

export interface LoginUserRequest extends AuthenticateUserRequest {}

export class LoginUserUseCase {
  constructor(
    private authRepository: IAuthRepository,
    private tokenService: ITokenService
  ) {}

  async execute(request: LoginUserRequest): Promise<AuthResponse> {
    // Authenticate with repository
    await this.authRepository.authenticateUser(request);

    // Get user profile
    const user = await this.authRepository.getUserByEmail(request.email);

    // Generate tokens
    const { accessToken, refreshToken } = this.tokenService.generateTokenPair(user);

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
          refreshToken,
        },
      },
      message: 'Login successful',
    };
  }
}
