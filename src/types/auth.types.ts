/**
 * User authentication and management types
 */

export interface UserRegistrationRequest {
  email: string;
  password: string;
  fullName: string;
}

export interface UserLoginRequest {
  email: string;
  password: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  email: string;
  resetCode: string;
  newPassword: string;
}

export interface GoogleAuthRequest {
  code: string;
  state?: string;
}

export interface UserProfile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  provider: 'cognito' | 'google';
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthResponse {
  success: boolean;
  message?: string;
  accessToken?: string;
  refreshToken?: string;
  user?: UserProfile;
}

export interface ApiErrorResponse {
  success: false;
  error: string;
  message?: string;
  details?: any;
}

export interface CognitoUser {
  Username: string;
  Attributes: Array<{
    Name: string;
    Value: string;
  }>;
  UserStatus: string;
  Enabled: boolean;
  UserCreateDate: Date;
  UserLastModifiedDate: Date;
}

export interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  given_name: string;
  family_name: string;
  picture?: string;
}

export interface JwtPayload {
  userId: string;
  email: string;
  type: 'access' | 'refresh';
  iat?: number;
  exp?: number;
}

export interface ValidationError {
  field: string;
  message: string;
}

export interface RateLimitInfo {
  limit: number;
  current: number;
  remaining: number;
  resetTime: Date;
}
