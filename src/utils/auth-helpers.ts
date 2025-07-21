import { container, TOKENS } from '../infrastructure/container/container';
import { CognitoTokenInvalidationService } from '../services/security/cognito-token-invalidation.service';
import { AuditLogService } from '../services/security/audit-log.service';

/**
 * Helper utilities for authentication operations
 */
export class AuthHelpers {
  /**
   * Invalidate all tokens for a user on logout
   */
  static async handleUserLogout(
    userId: string, 
    reason: string = 'user_logout',
    ip?: string,
    userAgent?: string,
    requestId?: string
  ): Promise<void> {
    try {
      // Invalidate tokens in Cognito
      const tokenInvalidationService = container.resolve<CognitoTokenInvalidationService>(
        TOKENS.TOKEN_INVALIDATION_SERVICE
      );
      
      await tokenInvalidationService.invalidateUserTokens(userId, reason);

      // Log logout event
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logAuthEvent({
        type: 'USER_LOGOUT',
        userId,
        ip: ip || 'unknown',
        userAgent: userAgent || 'unknown',
        requestId: requestId || 'unknown',
        details: {
          reason,
          invalidatedAt: new Date().toISOString(),
        },
      });

      console.log(`User ${userId} logged out successfully, tokens invalidated`);
    } catch (error) {
      console.error('Error handling user logout:', error);
      // Don't throw error - logout should still succeed even if token invalidation fails
    }
  }

  /**
   * Invalidate tokens for security reasons
   */
  static async handleSecurityLogout(
    userId: string,
    securityReason: string,
    ip?: string,
    userAgent?: string,
    requestId?: string
  ): Promise<void> {
    try {
      const tokenInvalidationService = container.resolve<CognitoTokenInvalidationService>(
        TOKENS.TOKEN_INVALIDATION_SERVICE
      );
      
      await tokenInvalidationService.invalidateTokensForSecurity(userId, securityReason);

      // Log security event
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logSecurityEvent({
        type: 'SECURITY_TOKEN_INVALIDATION',
        userId,
        ip: ip || 'unknown',
        userAgent: userAgent || 'unknown',
        requestId: requestId || 'unknown',
        details: {
          securityReason,
          invalidatedAt: new Date().toISOString(),
        },
      });

      console.log(`Security logout for user ${userId}: ${securityReason}`);
    } catch (error) {
      console.error('Error handling security logout:', error);
      throw error; // Security operations should fail if they can't complete
    }
  }

  /**
   * Invalidate tokens due to account changes
   */
  static async handleAccountChangeLogout(
    userId: string,
    changeReason: string,
    ip?: string,
    userAgent?: string,
    requestId?: string
  ): Promise<void> {
    try {
      const tokenInvalidationService = container.resolve<CognitoTokenInvalidationService>(
        TOKENS.TOKEN_INVALIDATION_SERVICE
      );
      
      await tokenInvalidationService.invalidateTokensForAccountChange(userId, changeReason);

      // Log account change event
      const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);
      await auditLog?.logAuthEvent({
        type: 'ACCOUNT_CHANGE_LOGOUT',
        userId,
        ip: ip || 'unknown',
        userAgent: userAgent || 'unknown',
        requestId: requestId || 'unknown',
        details: {
          changeReason,
          invalidatedAt: new Date().toISOString(),
        },
      });

      console.log(`Account change logout for user ${userId}: ${changeReason}`);
    } catch (error) {
      console.error('Error handling account change logout:', error);
      throw error; // Account changes should fail if tokens can't be invalidated
    }
  }

  /**
   * Check if user should be forced to re-authenticate
   */
  static shouldForceReauth(
    userLastLogout?: string,
    maxTokenAgeHours: number = 24
  ): boolean {
    if (!userLastLogout) {
      return false;
    }

    const maxTokenAgeMs = maxTokenAgeHours * 60 * 60 * 1000;
    const logoutTime = parseInt(userLastLogout);
    const timeSinceLogout = Date.now() - logoutTime;

    return timeSinceLogout > maxTokenAgeMs;
  }

  /**
   * Get user logout information
   */
  static getUserLogoutInfo(userLastLogout?: string, userLogoutReason?: string) {
    return {
      hasLoggedOut: !!userLastLogout,
      lastLogoutTime: userLastLogout ? new Date(parseInt(userLastLogout)) : undefined,
      logoutReason: userLogoutReason,
      logoutTimeAgo: userLastLogout 
        ? Date.now() - parseInt(userLastLogout)
        : undefined,
    };
  }
}

/**
 * Express middleware helper for logout functionality
 */
export const createLogoutHandler = () => {
  return async (req: any, res: any, next: any) => {
    if (req.user?.id) {
      await AuthHelpers.handleUserLogout(
        req.user.id,
        'api_logout',
        req.ip,
        req.headers['user-agent'],
        req.requestId
      );
    }
    next();
  };
};