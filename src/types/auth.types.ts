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
  roles: UserRole[];
  permissions: Permission[];
  features: string[];
  lastLogout?: string; // Timestamp of last logout for token invalidation
  logoutReason?: string; // Reason for logout (logout, security, etc.)
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthResponse {
  success?: boolean;
  data?: {
    user: {
      id: string;
      email: string;
      fullName: string;
      isVerified: boolean;
    };
    tokens: {
      accessToken: string;
      refreshToken: string;
    };
  };
  message?: string;
  error?: string;
}

export interface GeneralApiResponse {
  success: boolean;
  message?: string;
}

export interface ApiErrorResponse {
  success: false;
  error: string;
  message?: string;
  details?: unknown;
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

// User roles and permissions
export enum UserRole {
  ADMIN = 'admin',
  PREMIUM_USER = 'premium_user',
  BASIC_USER = 'basic_user',
  GUEST = 'guest',
}

export enum Permission {
  // Chat permissions
  CHAT_BASIC = 'chat:basic',
  CHAT_PREMIUM = 'chat:premium',
  CHAT_UNLIMITED = 'chat:unlimited',

  // Admin permissions
  ADMIN_USERS = 'admin:users',
  ADMIN_SYSTEM = 'admin:system',

  // Feature permissions
  FEATURE_VOICE_CHAT = 'feature:voice_chat',
  FEATURE_FILE_UPLOAD = 'feature:file_upload',
  FEATURE_CUSTOM_MODELS = 'feature:custom_models',
}

export interface UserPermissions {
  roles: UserRole[];
  permissions: Permission[];
  features: string[];
}

export interface CognitoJwtPayload {
  sub: string; // Cognito user ID
  iss: string; // Issuer
  client_id: string; // Client ID (Cognito uses this instead of aud for access tokens)
  token_use: 'access' | 'id';
  scope?: string;
  auth_time: number;
  iat: number;
  exp: number;
  jti: string; // JWT ID
  username?: string; // Username

  // User attributes (mostly present in ID tokens, may be missing in access tokens)
  email?: string;
  email_verified?: boolean;
  name?: string; // Full name
  given_name?: string; // First name
  family_name?: string; // Last name

  // Custom attributes for permissions and token management
  'custom:role'?: string;
  'custom:permissions'?: string;
  'custom:features'?: string;
  'custom:last_logout'?: string; // Last logout timestamp for token invalidation
  'custom:logout_reason'?: string; // Reason for logout

  // Additional Cognito-specific fields
  origin_jti?: string;
  event_id?: string;
}
