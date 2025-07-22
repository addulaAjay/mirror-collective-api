import { NextFunction, Request, Response } from 'express';
import { RateLimitInfo } from '../types/auth.types';

interface RateLimitOptions {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  message?: string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

interface RateLimitEntry {
  count: number;
  resetTime: Date;
  blocked: boolean;
}

class InMemoryRateLimitStore {
  private store = new Map<string, RateLimitEntry>();
  private cleanupInterval: any;

  constructor() {
    // Clean up expired entries every 5 minutes
    this.cleanupInterval = setInterval(
      () => {
        this.cleanup();
      },
      5 * 60 * 1000
    );
  }

  private cleanup(): void {
    const now = new Date();
    for (const [key, entry] of this.store.entries()) {
      if (entry.resetTime <= now) {
        this.store.delete(key);
      }
    }
  }

  get(key: string): RateLimitEntry | undefined {
    return this.store.get(key);
  }

  set(key: string, entry: RateLimitEntry): void {
    this.store.set(key, entry);
  }

  increment(key: string, windowMs: number): RateLimitEntry {
    const now = new Date();
    const existing = this.store.get(key);

    if (!existing || existing.resetTime <= now) {
      const newEntry: RateLimitEntry = {
        count: 1,
        resetTime: new Date(now.getTime() + windowMs),
        blocked: false,
      };
      this.store.set(key, newEntry);
      return newEntry;
    }

    existing.count++;
    this.store.set(key, existing);
    return existing;
  }

  block(key: string, durationMs: number): void {
    const entry = this.store.get(key);
    if (entry) {
      entry.blocked = true;
      entry.resetTime = new Date(Date.now() + durationMs);
      this.store.set(key, entry);
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

const store = new InMemoryRateLimitStore();

/**
 * Rate limiting middleware factory
 */
export const createRateLimit = (options: RateLimitOptions) => {
  const {
    windowMs,
    maxRequests,
    message = 'Too many requests, please try again later',
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Generate key based on IP and optionally user ID
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      const userId = req.user?.id || '';
      const key = `${ip}:${userId}`;

      // Check if blocked
      const existing = store.get(key);
      if (existing?.blocked) {
        res.status(429).json({
          success: false,
          error: 'Rate Limit Exceeded',
          message: 'Your account has been temporarily blocked due to too many failed attempts',
          rateLimitInfo: {
            limit: maxRequests,
            current: existing.count,
            remaining: 0,
            resetTime: existing.resetTime,
          } as RateLimitInfo,
        });
        return;
      }

      // Increment counter
      const entry = store.increment(key, windowMs);

      // Set rate limit headers
      res.set({
        'X-RateLimit-Limit': maxRequests.toString(),
        'X-RateLimit-Remaining': Math.max(0, maxRequests - entry.count).toString(),
        'X-RateLimit-Reset': Math.ceil(entry.resetTime.getTime() / 1000).toString(),
      });

      // Check if limit exceeded
      if (entry.count > maxRequests) {
        res.status(429).json({
          success: false,
          error: 'Rate Limit Exceeded',
          message,
          rateLimitInfo: {
            limit: maxRequests,
            current: entry.count,
            remaining: 0,
            resetTime: entry.resetTime,
          } as RateLimitInfo,
        });
        return;
      }

      // Continue with request
      next();

      // Optionally skip counting based on response
      if (skipSuccessfulRequests || skipFailedRequests) {
        res.on('finish', () => {
          const statusCode = res.statusCode;
          const shouldSkip =
            (skipSuccessfulRequests && statusCode < 400) ||
            (skipFailedRequests && statusCode >= 400);

          if (shouldSkip && entry.count > 0) {
            entry.count--;
            store.set(key, entry);
          }
        });
      }
    } catch (error) {
      console.error('Rate limiting error:', error);
      // Continue without rate limiting on error to avoid blocking legitimate requests
      next();
    }
  };
};

/**
 * Strict rate limiting for authentication endpoints
 */
export const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5, // 5 attempts per 15 minutes
  message: 'Too many authentication attempts, please try again in 15 minutes',
  skipSuccessfulRequests: true, // Don't count successful logins
});

/**
 * General API rate limiting
 */
export const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100, // 100 requests per 15 minutes
  message: 'Too many API requests, please try again later',
});

/**
 * Strict rate limiting for password reset attempts
 */
export const passwordResetRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 3, // 3 attempts per hour
  message: 'Too many password reset attempts, please try again in 1 hour',
});

/**
 * Block user after multiple failed authentication attempts
 */
export const createFailedAttemptTracker = (maxFailedAttempts: number, blockDurationMs: number) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Track failed attempts in response handler
    res.on('finish', () => {
      if (res.statusCode === 401 || res.statusCode === 403) {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const email = req.body?.email || '';
        const key = `failed_${ip}:${email}`;

        const entry = store.increment(key, blockDurationMs);

        if (entry.count >= maxFailedAttempts) {
          store.block(key, blockDurationMs);
        }
      }
    });

    next();
  };
};

/**
 * Failed login attempt tracker - blocks after 5 failed attempts for 30 minutes
 */
export const failedLoginTracker = createFailedAttemptTracker(
  5, // Max failed attempts
  30 * 60 * 1000 // 30 minutes block duration
);

// Clean up on process exit
process.on('SIGINT', () => store.destroy());
process.on('SIGTERM', () => store.destroy());
