import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { JwtService, CognitoService } from '../services';
import {
  AuthenticationError,
  RateLimitExceededError,
  ValidationError,
} from '../errors/auth.errors';
import { JwtPayload, UserProfile } from '../types/auth.types';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: UserProfile;
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
 * Authentication middleware for protecting routes
 */
export class AuthMiddleware {
  private jwtService: JwtService;
  private cognitoService: CognitoService;

  constructor() {
    this.jwtService = new JwtService();
    this.cognitoService = new CognitoService();
  }

  /**
   * Middleware to verify JWT access token
   */
  authenticateToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        throw new AuthenticationError('Authorization header is required');
      }

      if (!authHeader.startsWith('Bearer ')) {
        throw new AuthenticationError('Authorization header must start with Bearer');
      }

      const token = authHeader.substring(7); // Remove 'Bearer ' prefix

      if (!token) {
        throw new AuthenticationError('Access token is required');
      }

      // Verify the JWT token
      const decoded: JwtPayload = this.jwtService.verifyAccessToken(token);

      // Get user from Cognito to ensure user still exists
      const user = await this.cognitoService.getUserByEmail(decoded.email);

      // Attach user to request object
      req.user = user;

      next();
    } catch (error: any) {
      console.error('Authentication error:', error);

      if (error instanceof AuthenticationError) {
        res.status(error.statusCode).json({
          success: false,
          error: 'Authentication Failed',
          message: error.message,
        });
        return;
      }

      res.status(401).json({
        success: false,
        error: 'Authentication Failed',
        message: 'Invalid or expired token',
      });
    }
  };

  /**
   * Optional authentication middleware - doesn't fail if no token
   */
  optionalAuthentication = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);

        if (token) {
          const decoded: JwtPayload = this.jwtService.verifyAccessToken(token);
          const user = await this.cognitoService.getUserByEmail(decoded.email);
          req.user = user;
        }
      }

      next();
    } catch {
      // Silently continue without authentication
      next();
    }
  };

  /**
   * Middleware to check if user is authenticated (has valid user in request)
   */
  requireAuth = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication Required',
        message: 'You must be logged in to access this resource',
      });
      return;
    }

    next();
  };

  /**
   * Middleware to check if user has verified email
   */
  requireEmailVerification = (req: Request, res: Response, next: NextFunction): void => {
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
   * Create rate limiting middleware
   */
  static createRateLimit(
    options: {
      windowMs?: number;
      max?: number;
      message?: string;
      skipSuccessfulRequests?: boolean;
    } = {}
  ) {
    const defaultOptions = {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // 100 requests per window
      message: 'Too many requests from this IP, please try again later',
      skipSuccessfulRequests: false,
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req: Request, res: Response) => {
        res.status(429).json({
          success: false,
          error: 'Rate Limit Exceeded',
          message: options.message || 'Too many requests from this IP, please try again later',
          retryAfter: Math.ceil(options.windowMs! / 1000),
        });
      },
    };

    return rateLimit({ ...defaultOptions, ...options });
  }

  /**
   * Strict rate limiting for authentication endpoints
   */
  static authRateLimit = AuthMiddleware.createRateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many authentication attempts, please try again later',
    skipSuccessfulRequests: true,
  });

  /**
   * General API rate limiting
   */
  static apiRateLimit = AuthMiddleware.createRateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: 'Too many API requests, please try again later',
    skipSuccessfulRequests: false,
  });

  /**
   * Password reset rate limiting
   */
  static passwordResetRateLimit = AuthMiddleware.createRateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 password reset attempts per hour
    message: 'Too many password reset attempts, please try again later',
    skipSuccessfulRequests: true,
  });
}

/**
 * Validation middleware for request body
 */
export const validateRequestBody = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.body, { abortEarly: false });

    if (error) {
      const validationErrors = error.details.map((detail: any) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      res.status(400).json({
        success: false,
        error: 'Validation Failed',
        message: 'Invalid request data',
        details: validationErrors,
      });
      return;
    }

    // Replace req.body with validated value
    req.body = value;
    next();
  };
};

/**
 * Error handling middleware for authentication errors
 */
export const authErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  console.error('Authentication error:', error);

  if (error instanceof AuthenticationError) {
    res.status(error.statusCode).json({
      success: false,
      error: 'Authentication Error',
      message: error.message,
    });
    return;
  }

  if (error instanceof ValidationError) {
    res.status(error.statusCode).json({
      success: false,
      error: 'Validation Error',
      message: error.message,
      details: error.validationErrors,
    });
    return;
  }

  if (error instanceof RateLimitExceededError) {
    res.status(error.statusCode).json({
      success: false,
      error: 'Rate Limit Exceeded',
      message: error.message,
      retryAfter: error.retryAfter,
    });
    return;
  }

  // If not an operational error, don't expose details
  res.status(500).json({
    success: false,
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong',
  });
};

// Export instance for direct use
const authMiddlewareInstance = new AuthMiddleware();
export const authMiddleware = authMiddlewareInstance.authenticateToken;
