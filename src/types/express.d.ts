/**
 * Global type extensions for Express Request
 * This file extends the Express Request interface to include user and cognito context
 */

import { UserProfile } from './auth.types';

export interface CognitoAuthorizerContext {
  claims: {
    sub: string;
    email: string;
    email_verified: string;
    given_name?: string;
    family_name?: string;
    name?: string;
    'cognito:username': string;
    'cognito:groups'?: string[];
    aud: string;
    event_id: string;
    token_use: string;
    auth_time: number;
    iss: string;
    exp: number;
    iat: number;
  };
}

declare global {
  namespace Express {
    interface Request {
      user?: UserProfile;
      cognitoContext?: CognitoAuthorizerContext;
    }
  }
}
