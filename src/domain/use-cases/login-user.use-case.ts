import { AuthenticateUserRequest, IAuthRepository, ITokenService } from '../repositories';
import { UserProfile } from '../../types/auth.types';

export interface LoginUserRequest extends AuthenticateUserRequest {}

export interface LoginUserResponse {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  user?: UserProfile;
  data?: {
    user: UserProfile;
    tokens: {
      accessToken: string;
      refreshToken: string;
    };
  };
}

export class LoginUserUseCase {
  constructor(
    private authRepository: IAuthRepository,
    private tokenService: ITokenService
  ) {}

  async execute(request: LoginUserRequest): Promise<LoginUserResponse> {
    // Authenticate with repository
    await this.authRepository.authenticateUser(request);

    // Get user profile
    const user = await this.authRepository.getUserByEmail(request.email);
    // Generate tokens
    const { accessToken, refreshToken } = this.tokenService.generateTokenPair(user);
    return {
      success: true,
      accessToken,
      refreshToken,
      user,
      data: {
        user,
        tokens: {
          accessToken,
          refreshToken,
        },
      },
    };
  }
}
