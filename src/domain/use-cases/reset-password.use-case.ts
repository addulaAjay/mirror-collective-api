import { IAuthRepository } from '../repositories';

export interface InitiatePasswordResetRequest {
  email: string;
}

export interface InitiatePasswordResetResponse {
  success: boolean;
  message: string;
}

export interface ConfirmPasswordResetRequest {
  email: string;
  resetCode: string;
  newPassword: string;
}

export interface ConfirmPasswordResetResponse {
  success: boolean;
  message: string;
}

export class InitiatePasswordResetUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: InitiatePasswordResetRequest): Promise<InitiatePasswordResetResponse> {
    try {
      // Check if user exists
      await this.authRepository.getUserByEmail(request.email);

      // Initiate password reset
      await this.authRepository.initiatePasswordReset(request.email);

      return {
        success: true,
        message: 'Password reset instructions have been sent to your email address.',
      };
    } catch (error: any) {
      // For security reasons, we don't reveal if the user exists
      return {
        success: true,
        message: 'If an account with that email exists, password reset instructions have been sent.',
      };
    }
  }
}

export class ConfirmPasswordResetUseCase {
  constructor(private authRepository: IAuthRepository) {}

  async execute(request: ConfirmPasswordResetRequest): Promise<ConfirmPasswordResetResponse> {
    await this.authRepository.confirmPasswordReset(
      request.email,
      request.resetCode,
      request.newPassword
    );

    return {
      success: true,
      message: 'Password has been reset successfully. You can now log in with your new password.',
    };
  }
}