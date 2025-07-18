import { NextFunction, Request, Response } from 'express';
import {
  AuthenticationError,
  CognitoServiceError,
  EmailServiceError,
  GoogleOAuthError,
  InvalidTokenError,
  TokenExpiredError,
  UserAlreadyExistsError,
  UserNotFoundError,
} from '../errors/auth.errors';

export interface ErrorResponse {
  success: false;
  error: string;
  message: string;
  statusCode: number;
  timestamp: string;
  path: string;
  details?: any;
}

export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  console.error('Error occurred:', {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  const errorResponse: ErrorResponse = {
    success: false,
    error: error.constructor.name,
    message: error.message,
    statusCode: 500,
    timestamp: new Date().toISOString(),
    path: req.path,
  };

  // Handle specific error types
  if (error instanceof AuthenticationError) {
    errorResponse.statusCode = 401;
  } else if (error instanceof UserAlreadyExistsError) {
    errorResponse.statusCode = 409;
  } else if (error instanceof UserNotFoundError) {
    errorResponse.statusCode = 404;
  } else if (error instanceof InvalidTokenError || error instanceof TokenExpiredError) {
    errorResponse.statusCode = 401;
  } else if (error instanceof CognitoServiceError) {
    errorResponse.statusCode = 500;
    errorResponse.error = 'Authentication Service Error';
  } else if (error instanceof EmailServiceError) {
    errorResponse.statusCode = 500;
    errorResponse.error = 'Email Service Error';
  } else if (error instanceof GoogleOAuthError) {
    errorResponse.statusCode = 400;
    errorResponse.error = 'OAuth Error';
  } else if (error.name === 'ValidationError') {
    errorResponse.statusCode = 400;
    errorResponse.error = 'Validation Error';
  } else if (error.name === 'JsonWebTokenError') {
    errorResponse.statusCode = 401;
    errorResponse.error = 'Invalid Token';
    errorResponse.message = 'The provided token is invalid';
  } else if (error.name === 'TokenExpiredError') {
    errorResponse.statusCode = 401;
    errorResponse.error = 'Token Expired';
    errorResponse.message = 'The provided token has expired';
  }

  // Don't expose internal error details in production
  if (process.env.NODE_ENV === 'production' && errorResponse.statusCode >= 500) {
    errorResponse.message = 'Internal server error';
    delete errorResponse.details;
  }

  res.status(errorResponse.statusCode).json(errorResponse);
}