import { UserProfile } from '../../types/auth.types';

export interface CreateUserRequest {
  email: string;
  password: string;
  fullName: string;
}

export interface AuthenticateUserRequest {
  email: string;
  password: string;
}

export interface AuthenticationResult {
  accessToken: string;
  refreshToken: string;
  idToken: string;
}

export interface IAuthRepository {
  createUser(userData: CreateUserRequest): Promise<UserProfile>;
  authenticateUser(credentials: AuthenticateUserRequest): Promise<AuthenticationResult>;
  getUserByEmail(email: string): Promise<UserProfile>;
  initiatePasswordReset(email: string): Promise<void>;
  confirmPasswordReset(email: string, code: string, newPassword: string): Promise<void>;
  deleteUser(email: string): Promise<void>;
  // Email verification methods
  confirmEmailVerification(email: string, code: string): Promise<void>;
  resendEmailVerificationCode(email: string): Promise<void>;
}
