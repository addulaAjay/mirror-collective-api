/**
 * Custom error classes for authentication system
 */

export class AuthenticationError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number = 401) {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public validationErrors: Array<{ field: string; message: string }>;

  constructor(message: string, validationErrors: Array<{ field: string; message: string }> = []) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 400;
    this.isOperational = true;
    this.validationErrors = validationErrors;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class UserNotFoundError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string = 'User not found') {
    super(message);
    this.name = 'UserNotFoundError';
    this.statusCode = 404;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class UserAlreadyExistsError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string = 'User already exists') {
    super(message);
    this.name = 'UserAlreadyExistsError';
    this.statusCode = 409;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class TokenExpiredError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string = 'Token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
    this.statusCode = 401;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class InvalidTokenError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string = 'Invalid token') {
    super(message);
    this.name = 'InvalidTokenError';
    this.statusCode = 401;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class RateLimitExceededError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public retryAfter: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter: number = 900) {
    super(message);
    this.name = 'RateLimitExceededError';
    this.statusCode = 429;
    this.isOperational = true;
    this.retryAfter = retryAfter;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class CognitoServiceError extends Error {
  public statusCode: number;
  public isOperational: boolean;
  public cognitoErrorCode?: string;

  constructor(message: string, cognitoErrorCode?: string, statusCode: number = 500) {
    super(message);
    this.name = 'CognitoServiceError';
    this.statusCode = statusCode;
    this.isOperational = true;
    this.cognitoErrorCode = cognitoErrorCode;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class GoogleOAuthError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number = 400) {
    super(message);
    this.name = 'GoogleOAuthError';
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export class EmailServiceError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number = 500) {
    super(message);
    this.name = 'EmailServiceError';
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}
