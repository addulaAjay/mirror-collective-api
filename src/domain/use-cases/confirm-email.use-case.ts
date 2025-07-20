import { IAuthRepository } from '../repositories';

export interface ConfirmEmailRequest {
  email: string;
  code: string;
}

export interface ConfirmEmailResponse {
  success: boolean;
  message: string;
}

export class ConfirmEmailUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    await this.authRepository.confirmEmailVerification(request.email, request.code);

    return {
      success: true,
      message: 'Email verified successfully. You can now login.',
    };
  }
}
