import { CognitoIdentityProviderClient, AdminUpdateUserAttributesCommand } from '@aws-sdk/client-cognito-identity-provider';
import { CognitoJwtPayload, UserProfile } from '../../types/auth.types';

/**
 * Cognito-based token invalidation service
 * Uses custom attributes to track user logout times and token versions
 */
export class CognitoTokenInvalidationService {
  private cognitoClient: CognitoIdentityProviderClient;
  private userPoolId: string;

  constructor() {
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || '';
    
    if (!this.userPoolId) {
      throw new Error('COGNITO_USER_POOL_ID environment variable is required');
    }

    this.cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
  }

  /**
   * Invalidate all tokens for a user by updating their logout time
   */
  async invalidateUserTokens(userId: string, reason: string = 'logout'): Promise<void> {
    try {
      const now = Date.now().toString();
      
      const command = new AdminUpdateUserAttributesCommand({
        UserPoolId: this.userPoolId,
        Username: userId,
        UserAttributes: [
          {
            Name: 'custom:last_logout',
            Value: now,
          },
          {
            Name: 'custom:logout_reason',
            Value: reason,
          }
        ],
      });

      await this.cognitoClient.send(command);
      
      console.log(`Invalidated all tokens for user ${userId}, reason: ${reason}`);
    } catch (error) {
      console.error('Failed to invalidate user tokens:', error);
      throw new Error('Failed to invalidate user tokens');
    }
  }

  /**
   * Check if a token is still valid based on user's logout time
   */
  isTokenValid(tokenPayload: CognitoJwtPayload, userProfile: UserProfile): boolean {
    try {
      // Extract logout time from user profile (populated from Cognito attributes)
      const lastLogoutTime = userProfile.lastLogout;
      
      if (!lastLogoutTime) {
        // No logout time recorded, token is valid
        return true;
      }

      // Convert token issued time from seconds to milliseconds
      const tokenIssuedTime = tokenPayload.iat * 1000;
      const logoutTime = parseInt(lastLogoutTime);

      // Token is invalid if it was issued before the last logout
      if (tokenIssuedTime < logoutTime) {
        console.log(`Token invalid: issued at ${new Date(tokenIssuedTime).toISOString()}, user logged out at ${new Date(logoutTime).toISOString()}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error validating token:', error);
      // Fail secure - if we can't validate, consider token invalid
      return false;
    }
  }

  /**
   * Invalidate tokens for security reasons (password change, suspicious activity, etc.)
   */
  async invalidateTokensForSecurity(userId: string, reason: string): Promise<void> {
    await this.invalidateUserTokens(userId, `security:${reason}`);
  }

  /**
   * Invalidate tokens due to account changes (role change, permissions update, etc.)
   */
  async invalidateTokensForAccountChange(userId: string, reason: string): Promise<void> {
    await this.invalidateUserTokens(userId, `account_change:${reason}`);
  }

  /**
   * Get user's last logout information
   */
  getLastLogoutInfo(userProfile: UserProfile): {
    lastLogout?: string;
    logoutReason?: string;
    hasLoggedOut: boolean;
  } {
    return {
      lastLogout: userProfile.lastLogout,
      logoutReason: userProfile.logoutReason,
      hasLoggedOut: !!userProfile.lastLogout,
    };
  }

  /**
   * Check if user should be forced to re-authenticate
   * (useful for security policies)
   */
  shouldForceReauth(userProfile: UserProfile, maxTokenAgeMs: number = 24 * 60 * 60 * 1000): boolean {
    const lastLogout = userProfile.lastLogout;
    
    if (!lastLogout) {
      return false;
    }

    const logoutTime = parseInt(lastLogout);
    const timeSinceLogout = Date.now() - logoutTime;
    
    // Force re-auth if it's been too long since last logout
    return timeSinceLogout > maxTokenAgeMs;
  }

  /**
   * Bulk invalidate tokens for multiple users (admin operation)
   */
  async bulkInvalidateTokens(userIds: string[], reason: string): Promise<{
    successful: string[];
    failed: string[];
  }> {
    const successful: string[] = [];
    const failed: string[] = [];

    // Process in batches to avoid overwhelming Cognito
    const batchSize = 5;
    for (let i = 0; i < userIds.length; i += batchSize) {
      const batch = userIds.slice(i, i + batchSize);
      
      const promises = batch.map(async (userId) => {
        try {
          await this.invalidateUserTokens(userId, `bulk:${reason}`);
          successful.push(userId);
        } catch (error) {
          console.error(`Failed to invalidate tokens for user ${userId}:`, error);
          failed.push(userId);
        }
      });

      await Promise.all(promises);
      
      // Small delay between batches to be respectful to Cognito rate limits
      if (i + batchSize < userIds.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    return { successful, failed };
  }

  /**
   * Get statistics about token invalidation
   */
  async getInvalidationStats(userProfiles: UserProfile[]): Promise<{
    totalUsers: number;
    usersWithLogouts: number;
    usersNeedingReauth: number;
    recentLogouts: number;
  }> {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    
    let usersWithLogouts = 0;
    let usersNeedingReauth = 0;
    let recentLogouts = 0;

    userProfiles.forEach(user => {
      if (user.lastLogout) {
        usersWithLogouts++;
        
        const logoutTime = parseInt(user.lastLogout);
        if (logoutTime > oneHourAgo) {
          recentLogouts++;
        }
        
        if (this.shouldForceReauth(user)) {
          usersNeedingReauth++;
        }
      }
    });

    return {
      totalUsers: userProfiles.length,
      usersWithLogouts,
      usersNeedingReauth,
      recentLogouts,
    };
  }
}