import { IAuthRepository, IEmailService, CreateUserRequest } from '../repositories';
import { UserProfile } from '../../types/auth.types';
import { AuthResponse } from '../../types/auth.types';

export interface RegisterUserRequest extends CreateUserRequest {}

export interface RegisterUserResponse {
  success: boolean;
  message: string;
  user?: UserProfile;
}

export class RegisterUserUseCase {
  constructor(
    private authRepository: IAuthRepository,
    private emailService: IEmailService
  ) {}

  async execute(request: RegisterUserRequest): Promise<RegisterUserResponse> {
    // Pure business logic without infrastructure concerns
    const user = await this.authRepository.createUser(request);

    // Send welcome email (non-blocking)
    this.emailService.sendWelcomeEmail(user.email, user.firstName).catch((error) => {
      console.error('Failed to send welcome email:', error);
    });

    return {
      success: true,
      message: 'User registered successfully. Please check your email for verification.',
      user,
    };
  }
}