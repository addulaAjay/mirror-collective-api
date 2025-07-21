import { NextFunction, Request, Response } from 'express';
import { container, TOKENS } from '../infrastructure/container/container';
import { CognitoJwtService } from '../services/cognito/cognito-jwt.service';
import { TokenBlacklistService } from '../services/security/token-blacklist.service';
import { CognitoTokenInvalidationService } from '../services/security/cognito-token-invalidation.service';
import { AuditLogService } from '../services/security/audit-log.service';
import {
  CognitoJwtPayload,
  Permission,
  UserPermissions,
  UserProfile,
  UserRole,
} from '../types/auth.types';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: UserProfile;
      userPermissions?: UserPermissions;
      requestId?: string;
      rateLimitInfo?: {
        limit: number;
        current: number;
        remaining: number;
        resetTime: Date;
      };
    }
  }
}

/**
 * Enhanced JWT authentication middleware with additional security features
 */
export const enhancedAuthenticateJWT = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const requestId = (req as Request & { requestId?: string }).requestId || 'unknown';
  let auditLog: AuditLogService | null = null;

  try {
    // Get services from container
    auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
    const cognitoJwtService: CognitoJwtService = container.resolve(TOKENS.COGNITO_JWT_SERVICE);
    const tokenBlacklist: TokenBlacklistService = container.resolve(TOKENS.TOKEN_BLACKLIST_SERVICE);

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      await auditLog?.logSecurityEvent({
        type: 'AUTH_MISSING_HEADER',
        userId: null,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId,
        details: { path: req.path, method: req.method },
      });

      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Authorization header is required',
      });
      return;
    }

    if (!authHeader.startsWith('Bearer ')) {
      await auditLog?.logSecurityEvent({
        type: 'AUTH_INVALID_FORMAT',
        userId: null,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId,
        details: { authHeader: authHeader.substring(0, 20) },
      });

      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Authorization header must start with Bearer',
      });
      return;
    }

    const token = authHeader.substring(7);

    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'Access token is required',
      });
      return;
    }

    // Check if token is blacklisted
    if (await tokenBlacklist.isBlacklisted(token)) {
      await auditLog?.logSecurityEvent({
        type: 'AUTH_BLACKLISTED_TOKEN',
        userId: null,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId,
        details: { tokenHash: tokenBlacklist.hashToken(token).substring(0, 16) },
      });

      res.status(401).json({
        success: false,
        error: 'Authentication Failed',
        message: 'Token is no longer valid',
      });
      return;
    }

    try {
      // Verify token with Cognito
      const decoded: CognitoJwtPayload = await cognitoJwtService.verifyToken(token);
      console.log('Decoded JWT Payload:', decoded);

      // Additional token validation - check for essential claims
      // Cognito access tokens use 'client_id' instead of 'aud' and have 'token_use'
      if (!decoded.iss || !decoded.token_use || !decoded.client_id) {
        throw new Error('Token missing required claims');
      }

      // Verify this is an access token
      if (decoded.token_use !== 'access') {
        throw new Error('Invalid token type. Access token required.');
      }

      // Check token age (optional security measure)
      const tokenAge = Date.now() - decoded.iat * 1000;
      const maxTokenAge = 24 * 60 * 60 * 1000; // 24 hours
      if (tokenAge > maxTokenAge) {
        throw new Error('Token is too old, please re-authenticate');
      }

      // Extract user permissions
      const userPermissions: UserPermissions = cognitoJwtService.extractUserPermissions(decoded);

      // Create enhanced user profile
      // Note: Cognito access tokens may not contain email/user attributes
      // If email is missing, we may need to fetch it from Cognito user pool or use a placeholder
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

      // Validate token hasn't been invalidated via Cognito custom attributes
      const tokenInvalidationService = new CognitoTokenInvalidationService();
      if (!tokenInvalidationService.isTokenValid(decoded, userProfile)) {
        await auditLog?.logSecurityEvent({
          type: 'AUTH_INVALIDATED_TOKEN_USED',
          userId: userProfile.id,
          ip: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || 'unknown',
          requestId,
          details: {
            lastLogout: userProfile.lastLogout,
            logoutReason: userProfile.logoutReason,
            tokenIssuedAt: new Date(decoded.iat * 1000).toISOString(),
          },
        });

        res.status(401).json({
          success: false,
          error: 'Token Invalidated',
          message: 'Your session has been invalidated. Please log in again.',
        });
        return;
      }

      // Attach user and permissions to request
      req.user = userProfile;
      req.userPermissions = userPermissions;

      // Log successful authentication
      await auditLog?.logAuthEvent({
        type: 'AUTH_SUCCESS',
        userId: userProfile.id,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId,
        details: {
          roles: userPermissions.roles,
          path: req.path,
          method: req.method,
        },
      });

      next();
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Invalid token';

      await auditLog?.logSecurityEvent({
        type: 'AUTH_TOKEN_VERIFICATION_FAILED',
        userId: null,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId,
        details: {
          error: errorMessage,
          tokenHash: tokenBlacklist.hashToken(token).substring(0, 16),
        },
      });

      res.status(401).json({
        success: false,
        error: 'Authentication Failed',
        message: 'Invalid or expired token',
      });
      return;
    }
  } catch (error: unknown) {
    await auditLog?.logSecurityEvent({
      type: 'AUTH_MIDDLEWARE_ERROR',
      userId: null,
      ip: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      requestId,
      details: { error: error instanceof Error ? error.message : 'Unknown error' },
    });

    res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: 'Authentication service temporarily unavailable',
    });
    return;
  }
};

/**
 * Resource ownership authorization middleware
 */
export const requireResourceOwnership = (resourceIdParam: string = 'id') => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    // Admin users can access any resource
    if (req.userPermissions.roles.includes(UserRole.ADMIN)) {
      return next();
    }

    const resourceId = req.params[resourceIdParam];
    const userId = req.user.id;

    // Check if user owns the resource
    if (resourceId !== userId) {
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logSecurityEvent({
        type: 'UNAUTHORIZED_RESOURCE_ACCESS',
        userId: req.user.id,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId: (req as Request & { requestId?: string }).requestId || 'unknown',
        details: {
          requestedResource: resourceId,
          path: req.path,
          method: req.method,
        },
      });

      res.status(403).json({
        success: false,
        error: 'Access Denied',
        message: 'You can only access your own resources',
      });
      return;
    }

    next();
  };
};

/**
 * Enhanced role-based authorization with audit logging
 */
export const requireRoleEnhanced = (requiredRole: UserRole) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!req.userPermissions.roles.includes(requiredRole)) {
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logSecurityEvent({
        type: 'AUTHORIZATION_FAILED',
        userId: req.user.id,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId: (req as Request & { requestId?: string }).requestId || 'unknown',
        details: {
          requiredRole,
          userRoles: req.userPermissions.roles,
          path: req.path,
          method: req.method,
        },
      });

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
 * Enhanced permission-based authorization with audit logging
 */
export const requirePermissionEnhanced = (requiredPermission: Permission) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user || !req.userPermissions) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    if (!req.userPermissions.permissions.includes(requiredPermission)) {
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logSecurityEvent({
        type: 'AUTHORIZATION_FAILED',
        userId: req.user.id,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId: (req as Request & { requestId?: string }).requestId || 'unknown',
        details: {
          requiredPermission,
          userPermissions: req.userPermissions.permissions,
          path: req.path,
          method: req.method,
        },
      });

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
 * Session validation middleware
 */
export const validateSession = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  if (!req.user) {
    next();
    return;
  }

  try {
    // Check for concurrent session limit (optional feature)
    const maxConcurrentSessions = process.env.MAX_CONCURRENT_SESSIONS;
    if (maxConcurrentSessions) {
      // Implementation would require session store
      // For now, just log the session validation
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logAuthEvent({
        type: 'SESSION_VALIDATED',
        userId: req.user.id,
        ip: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        requestId: (req as Request & { requestId?: string }).requestId || 'unknown',
        details: { path: req.path, method: req.method },
      });
    }

    next();
  } catch {
    next();
  }
};
