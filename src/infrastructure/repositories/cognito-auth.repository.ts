import { IAuthRepository, CreateUserRequest, AuthenticateUserRequest, AuthenticationResult } from '../../domain/repositories/auth.repository';
import { UserProfile } from '../../types/auth.types';
import { CognitoService } from '../../services';

export class CognitoAuthRepository implements IAuthRepository {
  private cognitoService: CognitoService;

  constructor() {
    this.cognitoService = new CognitoService();
  }

  async createUser(userData: CreateUserRequest): Promise<UserProfile> {
    return this.cognitoService.createUser(
      userData.email,
      userData.password,
      userData.firstName,
      userData.lastName
    );
  }

  async authenticateUser(credentials: AuthenticateUserRequest): Promise<AuthenticationResult> {
    return this.cognitoService.authenticateUser(credentials.email, credentials.password);
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
}