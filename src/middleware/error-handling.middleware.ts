import { NextFunction, Request, Response } from 'express';
import { AuditLogService } from '../services/security/audit-log.service';
import { container, TOKENS } from '../infrastructure/container/container';

interface ErrorWithStatus extends Error {
  status?: number;
  statusCode?: number;
  details?: unknown;
  code?: string;
}

/**
 * Sanitize error messages to prevent information disclosure
 */
const sanitizeError = (error: ErrorWithStatus, isDevelopment: boolean) => {
  const isDev = isDevelopment || process.env.NODE_ENV === 'development';

  // Define safe error messages for production
  const safeErrors: Record<string, string> = {
    ValidationError: 'Invalid input provided',
    CastError: 'Invalid data format',
    MongoError: 'Database operation failed',
    JsonWebTokenError: 'Authentication failed',
    TokenExpiredError: 'Session expired',
    NotBeforeError: 'Authentication failed',
    AuthenticationError: 'Authentication failed',
    AuthorizationError: 'Access denied',
    RateLimitError: 'Rate limit exceeded',
    CognitoError: 'Authentication service error',
    AwsError: 'Service temporarily unavailable',
  };

  // Determine status code
  const statusCode = error.status || error.statusCode || 500;

  // Sanitize message
  let message = error.message || 'Internal server error';

  if (!isDev) {
    // In production, use safe generic messages
    if (statusCode >= 500) {
      message = 'Internal server error';
    } else if (statusCode >= 400) {
      message = safeErrors[error.name] || safeErrors[error.code || ''] || 'Bad request';
    }
  }

  return {
    statusCode,
    message,
    details: isDev ? error.details : undefined,
    stack: isDev ? error.stack : undefined,
  };
};

/**
 * Global error handling middleware
 */
export const globalErrorHandler = async (
  error: ErrorWithStatus,
  req: Request,
  res: Response,
  _next: NextFunction
): Promise<void> => {
  // Skip if response already sent
  if (res.headersSent) {
    return;
  }

  const requestId = (req as Request & { requestId?: string }).requestId || 'unknown';
  const isDevelopment = process.env.NODE_ENV === 'development';

  try {
    // Log error for audit purposes
    const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);

    await auditLog?.logSecurityEvent({
      type: 'APPLICATION_ERROR',
      userId: req.user?.id || null,
      ip: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      requestId,
      details: {
        error: error.name,
        message: error.message,
        statusCode: error.status || error.statusCode || 500,
        path: req.path,
        method: req.method,
        stack: isDevelopment ? error.stack : 'hidden',
      },
    });
  } catch (auditError) {
    console.error('Failed to log error to audit service:', auditError);
  }

  // Sanitize error for response
  const sanitizedError = sanitizeError(error, isDevelopment);

  // Log error to console (with full details in development)
  if (isDevelopment) {
    console.error('🚨 Application Error:', {
      message: error.message,
      stack: error.stack,
      requestId,
      path: req.path,
      method: req.method,
      userId: req.user?.id,
    });
  } else {
    console.error('Application Error:', {
      message: sanitizedError.message,
      statusCode: sanitizedError.statusCode,
      requestId,
      path: req.path,
    });
  }

  // Send error response
  res.status(sanitizedError.statusCode).json({
    success: false,
    error: sanitizedError.message,
    ...(typeof sanitizedError.details === 'object' && sanitizedError.details !== undefined
      ? { details: sanitizedError.details }
      : {}),
    ...(typeof sanitizedError.stack === 'string' && sanitizedError.stack !== undefined
      ? { stack: sanitizedError.stack }
      : {}),
    requestId,
    timestamp: new Date().toISOString(),
  });
};

/**
 * 404 Not Found handler
 */
export const notFoundHandler = async (
  req: Request,
  res: Response,
  _next: NextFunction
): Promise<void> => {
  const requestId = (req as Request & { requestId?: string }).requestId || 'unknown';

  try {
    // Log 404 attempts for security monitoring
    const auditLog = container.resolve<AuditLogService>(TOKENS.AUDIT_LOG_SERVICE);

    await auditLog?.logSecurityEvent({
      type: 'RESOURCE_NOT_FOUND',
      userId: req.user?.id || null,
      ip: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      requestId,
      details: {
        path: req.path,
        method: req.method,
        query: req.query,
      },
    });
  } catch (error) {
    console.error('Failed to log 404 to audit service:', error);
  }

  res.status(404).json({
    success: false,
    error: 'Resource not found',
    message: `The requested resource at ${req.path} was not found`,
    requestId,
    timestamp: new Date().toISOString(),
  });
};

/**
 * Async error wrapper to catch async/await errors
 */
export const asyncErrorHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Validation error handler
 */
export const validationErrorHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Handle Joi validation errors
  if ((error as any).isJoi || (error as any).name === 'ValidationError') {
    const validationErrors =
      (error as any).details?.map((detail: any) => ({
        field: detail.path?.join('.') || 'unknown',
        message: detail.message,
      })) || [];

    res.status(400).json({
      success: false,
      error: 'Validation Error',
      message: 'One or more fields contain invalid data',
      validationErrors,
      requestId: (req as Request & { requestId?: string }).requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  next(error);
};

/**
 * Database error handler
 */
export const databaseErrorHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Handle MongoDB duplicate key errors
  if ((error as any).code === 11000) {
    const field = Object.keys((error as any).keyValue || {})[0] || 'field';
    res.status(409).json({
      success: false,
      error: 'Duplicate Entry',
      message: `A record with this ${field} already exists`,
      requestId: (req as Request & { requestId?: string }).requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Handle MongoDB cast errors
  if ((error as any).name === 'CastError') {
    res.status(400).json({
      success: false,
      error: 'Invalid Data Format',
      message: 'Invalid ID format provided',
      requestId: (req as Request & { requestId?: string }).requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  next(error);
};

/**
 * JWT error handler
 */
export const jwtErrorHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if ((error as any).name === 'JsonWebTokenError') {
    res.status(401).json({
      success: false,
      error: 'Authentication Failed',
      message: 'Invalid authentication token',
      requestId: (req as Request & { requestId?: string }).requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  if ((error as any).name === 'TokenExpiredError') {
    res.status(401).json({
      success: false,
      error: 'Session Expired',
      message: 'Your session has expired. Please log in again',
      requestId: (req as Request & { requestId?: string }).requestId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  next(error);
};

/**
 * Combined error handling middleware chain
 */
export const errorHandlingChain = [
  validationErrorHandler,
  databaseErrorHandler,
  jwtErrorHandler,
  globalErrorHandler,
];

/**
 * Process error handler for uncaught exceptions and rejections
 */
export const setupProcessErrorHandlers = (): void => {
  process.on('uncaughtException', (error: Error) => {
    console.error('🚨 Uncaught Exception:', error);

    // Log to file or external service in production
    if (process.env.NODE_ENV === 'production') {
      // Log to external service
      console.error('Uncaught Exception - Server shutting down');
      process.exit(1);
    }
  });

  process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
    console.error('🚨 Unhandled Promise Rejection:', reason);
    console.error('Promise:', promise);

    if (process.env.NODE_ENV === 'production') {
      // Log to external service
      console.error('Unhandled Rejection - Server shutting down');
      process.exit(1);
    }
  });
};
