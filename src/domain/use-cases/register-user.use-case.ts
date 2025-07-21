import { CreateUserRequest, IAuthRepository } from '../repositories';
import { UserProfile } from '../../types/auth.types';

export interface RegisterUserRequest extends CreateUserRequest {}

export interface RegisterUserResponse {
  success: boolean;
  message: string;
  user?: UserProfile;
}

export class RegisterUserUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: RegisterUserRequest): Promise<RegisterUserResponse> {
    // Pure business logic without infrastructure concerns
    const user = await this.authRepository.createUser(request);

    return {
      success: true,
      message: 'User registered successfully. Please check your email for verification.',
      user,
    };
  }
}
