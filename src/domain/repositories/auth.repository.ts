import { UserProfile } from '../../types/auth.types';

export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
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
}