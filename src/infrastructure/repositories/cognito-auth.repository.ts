import {
  AuthenticateUserRequest,
  AuthenticationResult,
  CreateUserRequest,
  IAuthRepository,
} from '../../domain/repositories/auth.repository';
import { UserProfile } from '../../types/auth.types';
import { CognitoService } from '../../services';

export class CognitoAuthRepository implements IAuthRepository {
  private cognitoService: CognitoService;

  constructor() {
    this.cognitoService = new CognitoService();
  }

  async createUser(userData: CreateUserRequest): Promise<UserProfile> {
    const nameParts = userData.fullName.trim().split(/\s+/);
    const firstName = nameParts[0] || '';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';
    const signUpResult = await this.cognitoService.signUpUser(
      userData.email,
      userData.password,
      firstName,
      lastName
    );
    return {
      id: signUpResult.userSub,
      email: userData.email,
      firstName,
      lastName,
      provider: 'cognito',
      emailVerified: false, // User needs to verify email
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      roles: [],
      permissions: [],
      features: [],
    };
  }

  async authenticateUser(credentials: AuthenticateUserRequest): Promise<AuthenticationResult> {
    return this.cognitoService.authenticateUser(credentials.email, credentials.password);
  }

  async refreshToken(refreshToken: string): Promise<AuthenticationResult> {
    return this.cognitoService.refreshAccessToken(refreshToken);
  }

  async getUserByEmail(email: string): Promise<UserProfile> {
    return this.cognitoService.getUserByEmail(email);
  }

  async initiatePasswordReset(email: string): Promise<void> {
    return this.cognitoService.initiatePasswordReset(email);
  }

  async confirmPasswordReset(email: string, code: string, newPassword: string): Promise<void> {
    return this.cognitoService.confirmPasswordReset(email, code, newPassword);
  }

  async deleteUser(email: string): Promise<void> {
    return this.cognitoService.deleteUser(email);
  }

  async confirmEmailVerification(email: string, code: string): Promise<void> {
    return this.cognitoService.confirmSignUp(email, code);
  }

  async resendEmailVerificationCode(email: string): Promise<void> {
    return this.cognitoService.resendConfirmationCode(email);
  }
}
