/**
 * Middleware to extract user information from API Gateway Cognito authorizer context
 * This middleware runs for protected endpoints that use API Gateway Cognito authorization
 * Also handles local development by providing mock user data
 */

import { NextFunction, Request, Response } from 'express';
import { UserProfile, UserRole } from '../types/auth.types';

// Define the interface locally to avoid import issues
interface CognitoAuthorizerContext {
  claims: {
    sub: string; // User ID
    email: string;
    email_verified: string;
    given_name?: string;
    family_name?: string;
    name?: string;
    'cognito:username': string;
    'cognito:groups'?: string[];
    aud: string; // Audience (client ID)
    event_id: string;
    token_use: string;
    auth_time: number;
    iss: string; // Issuer
    exp: number; // Expiration
    iat: number; // Issued at
  };
}

// Extended Request interface for this middleware
interface AuthenticatedRequest extends Request {
  user?: UserProfile;
  cognitoContext?: CognitoAuthorizerContext;
}

// Extended interface for Lambda proxy requests
interface LambdaProxyRequest extends AuthenticatedRequest {
  requestContext?: {
    authorizer?: {
      claims?: CognitoAuthorizerContext['claims'];
    } & CognitoAuthorizerContext['claims'];
  };
}

/**
 * Extract user information from API Gateway Cognito authorizer context
 * This middleware handles both local development and production deployment
 */
export const extractCognitoUser = (req: Request, res: Response, next: NextFunction): void => {
  const authReq = req as AuthenticatedRequest;
  try {
    const isLocal = process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test';

    if (isLocal) {
      // Local development: Use mock user data or extract from JWT if available
      handleLocalDevelopment(authReq, res, next);
    } else {
      // Production: Extract user from API Gateway Cognito authorizer context
      handleProductionAPIGateway(authReq, res, next);
    }
  } catch (error) {
    console.error('Error extracting Cognito user:', error);
    res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: 'Failed to extract user information',
    });
  }
};

/**
 * Handle local development by providing mock user or decoding JWT token
 */
function handleLocalDevelopment(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  // For local development, if no auth header is provided, use a mock user
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('🔧 Local development: Using mock user (no auth header)');

    const mockClaims: CognitoAuthorizerContext['claims'] = {
      sub: 'mock-user-123',
      email: 'mock@localhost.dev',
      email_verified: 'true',
      given_name: 'Mock',
      family_name: 'User',
      name: 'Mock User',
      'cognito:username': 'mockuser',
      'cognito:groups': ['basic_user'],
      aud: 'mock-client-id',
      event_id: 'mock-event-id',
      token_use: 'access',
      auth_time: Math.floor(Date.now() / 1000),
      iss: 'https://cognito-idp.us-east-1.amazonaws.com/mock-pool',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    populateUserFromClaims(req, mockClaims);
    next();
    return;
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  // Try to decode JWT token for more realistic local testing
  try {
    const [, payloadBase64] = token.split('.');
    if (!payloadBase64) {
      throw new Error('Invalid JWT format');
    }

    // Decode base64 payload
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
    console.log('🔧 Local development: Decoded JWT token for user:', payload.email || payload.sub);

    // Create Cognito-like claims from JWT payload
    const claims: CognitoAuthorizerContext['claims'] = {
      sub: payload.sub || 'decoded-user-id',
      email: payload.email || 'decoded@localhost.dev',
      email_verified: payload.email_verified || 'true',
      given_name: payload.given_name || payload.name?.split(' ')[0] || 'Decoded',
      family_name: payload.family_name || payload.name?.split(' ').slice(1).join(' ') || 'User',
      name: payload.name || 'Decoded User',
      'cognito:username':
        payload['cognito:username'] || payload.preferred_username || 'decodeduser',
      'cognito:groups': payload['cognito:groups'] || ['basic_user'],
      aud: payload.aud || 'local-client-id',
      event_id: 'local-event-id',
      token_use: payload.token_use || 'access',
      auth_time: payload.auth_time || Math.floor(Date.now() / 1000),
      iss: payload.iss || 'https://cognito-idp.us-east-1.amazonaws.com/local-pool',
      exp: payload.exp || Math.floor(Date.now() / 1000) + 3600,
      iat: payload.iat || Math.floor(Date.now() / 1000),
    };

    populateUserFromClaims(req, claims);
    next();
  } catch (error) {
    console.warn('🔧 Local development: JWT decode failed, using fallback mock user:', error);

    // Fallback to mock user if JWT decode fails
    const mockClaims: CognitoAuthorizerContext['claims'] = {
      sub: 'fallback-user-456',
      email: 'fallback@localhost.dev',
      email_verified: 'true',
      given_name: 'Fallback',
      family_name: 'User',
      name: 'Fallback User',
      'cognito:username': 'fallbackuser',
      'cognito:groups': ['basic_user'],
      aud: 'fallback-client-id',
      event_id: 'fallback-event-id',
      token_use: 'access',
      auth_time: Math.floor(Date.now() / 1000),
      iss: 'https://cognito-idp.us-east-1.amazonaws.com/fallback-pool',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    populateUserFromClaims(req, mockClaims);
    next();
  }
}

/**
 * Handle production deployment with API Gateway Cognito authorizer
 */
function handleProductionAPIGateway(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const lambdaRequest = req as LambdaProxyRequest;
  const requestContext = lambdaRequest.requestContext;

  if (!requestContext?.authorizer) {
    res.status(401).json({
      success: false,
      error: 'Authentication Required',
      message: 'No authorizer context found',
    });
    return;
  }

  const authorizer = requestContext.authorizer;
  const claims = authorizer.claims || authorizer;

  if (!claims || !claims.sub) {
    res.status(401).json({
      success: false,
      error: 'Authentication Required',
      message: 'Invalid authorizer context',
    });
    return;
  }

  console.log(
    '🚀 Production: Using API Gateway Cognito authorizer context for user:',
    claims.email
  );
  populateUserFromClaims(req, claims);
  next();
}

/**
 * Common function to populate user from Cognito claims
 */
function populateUserFromClaims(
  req: AuthenticatedRequest,
  claims: CognitoAuthorizerContext['claims']
): void {
  // Store the raw Cognito context for advanced use cases
  (req as any).cognitoContext = { claims };

  // Create a UserProfile object from Cognito claims
  const userProfile: UserProfile = {
    id: claims.sub,
    email: claims.email,
    firstName: claims.given_name || claims.name?.split(' ')[0] || '',
    lastName: claims.family_name || claims.name?.split(' ').slice(1).join(' ') || '',
    provider: 'cognito',
    emailVerified: claims.email_verified === 'true',
    createdAt: new Date(claims.auth_time * 1000).toISOString(),
    updatedAt: new Date().toISOString(),
    roles: [], // Will be populated from Cognito groups if available
    permissions: [], // Will be populated from business logic if needed
    features: [], // Will be populated from business logic if needed
  };

  // Extract roles from Cognito groups if available (map to UserRole enum values)
  if (claims['cognito:groups']) {
    userProfile.roles = claims['cognito:groups']
      .map((group: string) => {
        // Map Cognito group names to UserRole enum values
        switch (group.toLowerCase()) {
          case 'admin':
          case 'administrators':
            return UserRole.ADMIN;
          case 'premium':
          case 'premium_user':
          case 'premium_users':
            return UserRole.PREMIUM_USER;
          case 'basic':
          case 'basic_user':
          case 'basic_users':
            return UserRole.BASIC_USER;
          default:
            return UserRole.GUEST; // Default fallback
        }
      })
      .filter((role, index, self) => self.indexOf(role) === index); // Remove duplicates
  }

  (req as any).user = userProfile;
}

/**
 * Utility function to get user ID from request (for use in controllers)
 */
export const getUserId = (req: Request): string | null => {
  const authReq = req as AuthenticatedRequest;
  return authReq.user?.id || authReq.cognitoContext?.claims?.sub || null;
};

/**
 * Utility function to get user email from request (for use in controllers)
 */
export const getUserEmail = (req: Request): string | null => {
  const authReq = req as AuthenticatedRequest;
  return authReq.user?.email || authReq.cognitoContext?.claims?.email || null;
};

// Make this file a proper ES module
export {};
