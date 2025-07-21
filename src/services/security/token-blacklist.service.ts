import { createHash } from 'crypto';

interface BlacklistedToken {
  tokenHash: string;
  userId: string;
  blacklistedAt: Date;
  expiresAt: Date;
  reason: string;
}

/**
 * Token blacklist service to prevent reuse of invalidated tokens
 */
export class TokenBlacklistService {
  private blacklistedTokens = new Map<string, BlacklistedToken>();
  private cleanupInterval: any;

  constructor() {
    // Clean up expired tokens every 15 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 15 * 60 * 1000);
  }

  /**
   * Hash a token for secure storage
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Add a token to the blacklist
   */
  async blacklistToken(
    token: string,
    userId: string,
    reason: string,
    expiresAt?: Date
  ): Promise<void> {
    const tokenHash = this.hashToken(token);
    const defaultExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const blacklistedToken: BlacklistedToken = {
      tokenHash,
      userId,
      blacklistedAt: new Date(),
      expiresAt: expiresAt || defaultExpiry,
      reason,
    };

    this.blacklistedTokens.set(tokenHash, blacklistedToken);
  }

  /**
   * Check if a token is blacklisted
   */
  async isBlacklisted(token: string): Promise<boolean> {
    const tokenHash = this.hashToken(token);
    const blacklistedToken = this.blacklistedTokens.get(tokenHash);

    if (!blacklistedToken) {
      return false;
    }

    // Check if blacklist entry has expired
    if (blacklistedToken.expiresAt <= new Date()) {
      this.blacklistedTokens.delete(tokenHash);
      return false;
    }

    return true;
  }

  /**
   * Blacklist all tokens for a specific user
   */
  async blacklistAllUserTokens(userId: string, reason: string): Promise<void> {
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    // This is a simplified implementation
    // In a production system, you'd need to track all active tokens per user
    // For now, we'll just mark the user for token invalidation
    const userBlacklistEntry: BlacklistedToken = {
      tokenHash: `user_${userId}`,
      userId,
      blacklistedAt: new Date(),
      expiresAt,
      reason,
    };

    this.blacklistedTokens.set(`user_${userId}`, userBlacklistEntry);
  }

  /**
   * Check if all tokens for a user are blacklisted
   */
  async areAllUserTokensBlacklisted(userId: string): Promise<boolean> {
    const userEntry = this.blacklistedTokens.get(`user_${userId}`);
    
    if (!userEntry) {
      return false;
    }

    // Check if blacklist entry has expired
    if (userEntry.expiresAt <= new Date()) {
      this.blacklistedTokens.delete(`user_${userId}`);
      return false;
    }

    return true;
  }

  /**
   * Remove a token from the blacklist (whitelist it)
   */
  async whitelistToken(token: string): Promise<void> {
    const tokenHash = this.hashToken(token);
    this.blacklistedTokens.delete(tokenHash);
  }

  /**
   * Get blacklisted tokens for a user (for administrative purposes)
   */
  async getUserBlacklistedTokens(userId: string): Promise<BlacklistedToken[]> {
    const userTokens: BlacklistedToken[] = [];

    for (const [, blacklistedToken] of this.blacklistedTokens.entries()) {
      if (blacklistedToken.userId === userId && blacklistedToken.expiresAt > new Date()) {
        userTokens.push(blacklistedToken);
      }
    }

    return userTokens;
  }

  /**
   * Get blacklist statistics
   */
  async getBlacklistStats(): Promise<{
    totalBlacklisted: number;
    activeBlacklisted: number;
    expiredBlacklisted: number;
  }> {
    const now = new Date();
    let activeCount = 0;
    let expiredCount = 0;

    for (const blacklistedToken of this.blacklistedTokens.values()) {
      if (blacklistedToken.expiresAt > now) {
        activeCount++;
      } else {
        expiredCount++;
      }
    }

    return {
      totalBlacklisted: this.blacklistedTokens.size,
      activeBlacklisted: activeCount,
      expiredBlacklisted: expiredCount,
    };
  }

  /**
   * Clean up expired blacklisted tokens
   */
  private cleanup(): void {
    const now = new Date();
    const expiredTokens: string[] = [];

    for (const [tokenHash, blacklistedToken] of this.blacklistedTokens.entries()) {
      if (blacklistedToken.expiresAt <= now) {
        expiredTokens.push(tokenHash);
      }
    }

    expiredTokens.forEach(hash => {
      this.blacklistedTokens.delete(hash);
    });
  }

  /**
   * Clear all blacklisted tokens (for testing/admin purposes)
   */
  async clearAll(): Promise<void> {
    this.blacklistedTokens.clear();
  }

  /**
   * Clean up resources
   */
  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.blacklistedTokens.clear();
  }
}

// Cleanup on process exit
process.on('SIGINT', () => {
  // This would be handled by DI container cleanup in production
});

process.on('SIGTERM', () => {
  // This would be handled by DI container cleanup in production
});