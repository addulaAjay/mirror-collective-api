import { NextFunction, Request, Response } from 'express';
import { container, TOKENS } from '../infrastructure/container/container';
import {
  CognitoJwtPayload,
  Permission,
  UserPermissions,
  UserProfile,
  UserRole,
} from '../types/auth.types';
import { CognitoJwtService } from '../services/cognito/cognito-jwt.service';

// Extend Express Request interface to include user and permissions
declare global {
  namespace Express {
    interface Request {
      user?: UserProfile;
      userPermissions?: UserPermissions;
    }
  }
}

/**
 * JWT authentication middleware with Cognito verification and role-based access control
 */
export const authenticateJWT = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Authorization header is required',
      });
      return;
    }

    if (!authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Authorization header must start with Bearer',
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Access token is required',
      });
      return;
    }

    try {
      // Get Cognito JWT service from container
      const cognitoJwtService: CognitoJwtService = container.resolve(TOKENS.COGNITO_JWT_SERVICE);

      // Verify token with Cognito
      const decoded: CognitoJwtPayload = await cognitoJwtService.verifyToken(token);

      // Extract user permissions from Cognito custom attributes
      const userPermissions: UserPermissions = cognitoJwtService.extractUserPermissions(decoded);

      // Create user profile directly from JWT claims (no database lookup)
      const userProfile: UserProfile = {
        id: decoded.sub,
        email: decoded.email || '', // Use empty string if email not in token
        firstName: decoded.given_name || decoded.name?.split(' ')[0] || '',
        lastName: decoded.family_name || decoded.name?.split(' ').slice(1).join(' ') || '',
        provider: 'cognito',
        emailVerified: decoded.email_verified || false, // Default to false if not present
        createdAt: new Date(decoded.auth_time * 1000).toISOString(),
        updatedAt: new Date().toISOString(),
        roles: userPermissions.roles,
        permissions: userPermissions.permissions,
        features: userPermissions.features,
        lastLogout: decoded['custom:last_logout'],
        logoutReason: decoded['custom:logout_reason'],
      };

      // Attach user and permissions to request object
      req.user = userProfile;
      req.userPermissions = userPermissions;

      next();
    } catch (error: unknown) {
      console.error('Token verification failed:', error);
      res.status(401).json({
        success: false,
        error: 'Authentication Failed',
        message: error instanceof Error ? error.message : 'Invalid or expired token',
      });
      return;
    }
  } catch (error: unknown) {
    console.error('Authentication middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: 'Authentication service temporarily unavailable',
    });
    return;
  }
};

/**
 * Optional JWT authentication middleware - doesn't fail if no token
 */
export const optionalAuthenticateJWT = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);

      if (token) {
        try {
          // Get Cognito JWT service from container
          const cognitoJwtService: CognitoJwtService = container.resolve(
            TOKENS.COGNITO_JWT_SERVICE
          );

          // Verify token with Cognito
          const decoded: CognitoJwtPayload = await cognitoJwtService.verifyToken(token);

          // Extract user permissions
          const userPermissions: UserPermissions =
            cognitoJwtService.extractUserPermissions(decoded);

          // Create user profile directly from JWT claims (no database lookup)
          const userProfile: UserProfile = {
            id: decoded.sub,
            email: decoded.email || '', // Use empty string if email not in token
            firstName: decoded.given_name || decoded.name?.split(' ')[0] || '',
            lastName: decoded.family_name || decoded.name?.split(' ').slice(1).join(' ') || '',
            provider: 'cognito',
            emailVerified: decoded.email_verified || false, // Default to false if not present
            createdAt: new Date(decoded.auth_time * 1000).toISOString(),
            updatedAt: new Date().toISOString(),
            roles: userPermissions.roles,
            permissions: userPermissions.permissions,
            features: userPermissions.features,
            lastLogout: decoded['custom:last_logout'],
            logoutReason: decoded['custom:logout_reason'],
          };

          req.user = userProfile;
          req.userPermissions = userPermissions;
        } catch {
          // Silently continue without authentication on any error
        }
      }
    }

    next();
  } catch {
    // Silently continue without authentication on any error
    next();
  }
};

/**
 * Middleware to check if user has verified email
 */
export const requireEmailVerification = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication Required',
      message: 'You must be logged in to access this resource',
    });
    return;
  }

  if (!req.user.emailVerified) {
    res.status(403).json({
      success: false,
      error: 'Email Verification Required',
      message: 'Please verify your email address to access this resource',
    });
    return;
  }

  next();
};

/**
 * Role-based authorization middleware
 */
export const requireRole = (requiredRole: UserRole) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!req.userPermissions.roles.includes(requiredRole)) {
      res.status(403).json({
        success: false,
        error: 'Insufficient Permissions',
        message: `This resource requires ${requiredRole} role`,
      });
      return;
    }

    next();
  };
};

/**
 * Permission-based authorization middleware
 */
export const requirePermission = (requiredPermission: Permission) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!req.userPermissions.permissions.includes(requiredPermission)) {
      res.status(403).json({
        success: false,
        error: 'Insufficient Permissions',
        message: `This resource requires ${requiredPermission} permission`,
      });
      return;
    }

    next();
  };
};

/**
 * Feature-based authorization middleware
 */
export const requireFeature = (requiredFeature: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!req.userPermissions.features.includes(requiredFeature)) {
      res.status(403).json({
        success: false,
        error: 'Feature Not Available',
        message: `This feature is not available for your account: ${requiredFeature}`,
      });
      return;
    }

    next();
  };
};

/**
 * Combined authorization middleware - requires any of the specified roles
 */
export const requireAnyRole = (roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    const hasAnyRole = roles.some((role) => req.userPermissions?.roles.includes(role));
    if (!hasAnyRole) {
      res.status(403).json({
        success: false,
        error: 'Insufficient Permissions',
        message: `This resource requires one of these roles: ${roles.join(', ')}`,
      });
      return;
    }

    next();
  };
};

/**
 * Combined authorization middleware - requires any of the specified permissions
 */
export const requireAnyPermission = (permissions: Permission[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    const hasAnyPermission = permissions.some((permission) =>
      req.userPermissions?.permissions.includes(permission)
    );
    if (!hasAnyPermission) {
      res.status(403).json({
        success: false,
        error: 'Insufficient Permissions',
        message: `This resource requires one of these permissions: ${permissions.join(', ')}`,
      });
      return;
    }

    next();
  };
};
