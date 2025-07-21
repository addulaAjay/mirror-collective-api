import { IAuthRepository } from '../repositories';

export interface ResendVerificationCodeRequest {
  email: string;
}

export interface ResendVerificationCodeResponse {
  success: boolean;
  message: string;
}

export class ResendVerificationCodeUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: ResendVerificationCodeRequest): Promise<ResendVerificationCodeResponse> {
    await this.authRepository.resendEmailVerificationCode(request.email);

    return {
      success: true,
      message: 'Verification code has been sent to your email.',
    };
  }
}
