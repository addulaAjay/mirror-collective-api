import { NextFunction, Request, Response } from 'express';

/**
 * Security headers middleware to protect against common vulnerabilities
 */
export const securityHeaders = (req: Request, res: Response, next: NextFunction): void => {
  // Content Security Policy - Prevent XSS attacks
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://apis.google.com https://accounts.google.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self' https://api.openai.com https://cognito-idp.*.amazonaws.com",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );

  // Prevent clickjacking attacks
  res.setHeader('X-Frame-Options', 'DENY');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Referrer Policy - Control referrer information
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy - Control browser features
  res.setHeader(
    'Permissions-Policy',
    [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
    ].join(', ')
  );

  // Prevent caching of sensitive data
  if (req.path.includes('/auth/') || req.path.includes('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  // Remove server information
  res.removeHeader('X-Powered-By');

  next();
};

/**
 * HTTPS redirect middleware for production
 */
export const httpsRedirect = (req: Request, res: Response, next: NextFunction): void => {
  // Only enforce HTTPS in production
  if (process.env.NODE_ENV === 'production') {
    // Check if request is not HTTPS
    if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
      return res.redirect(301, `https://${req.get('host')}${req.url}`);
    }

    // Set Strict Transport Security header for HTTPS
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload'
    );
  }

  next();
};

/**
 * CORS configuration middleware
 */
export const corsConfig = (req: Request, res: Response, next: NextFunction): void => {
  const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://mirror-collective.com',
    'https://app.mirror-collective.com',
    process.env.FRONTEND_URL,
  ].filter(Boolean);

  const origin = req.headers.origin;

  // Check if origin is allowed
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  // Allow credentials
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Allowed headers
  res.setHeader(
    'Access-Control-Allow-Headers',
    [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-CSRF-Token',
      'X-Rate-Limit-Remaining',
      'X-Rate-Limit-Reset',
    ].join(', ')
  );

  // Allowed methods
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD'
  );

  // Preflight response for OPTIONS requests
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  next();
};

/**
 * API versioning header middleware
 */
export const apiVersioning = (req: Request, res: Response, next: NextFunction): void => {
  // Set API version header
  res.setHeader('X-API-Version', '1.0.0');
  
  // Accept API version from client
  const clientVersion = req.headers['x-api-version'] || req.headers['api-version'];
  if (clientVersion && clientVersion !== '1.0.0') {
    res.status(400).json({
      success: false,
      error: 'API Version Mismatch',
      message: `Unsupported API version: ${clientVersion}. Current version: 1.0.0`,
    });
    return;
  }

  next();
};

/**
 * Request ID middleware for request tracing
 */
export const requestId = (req: Request, res: Response, next: NextFunction): void => {
  const requestId = req.headers['x-request-id'] || 
    `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Add request ID to request object for logging
  (req as Request & { requestId: string }).requestId = requestId.toString();
  
  // Set response header
  res.setHeader('X-Request-ID', requestId.toString());

  next();
};

/**
 * Combined security middleware - applies all security headers
 */
export const applySecurity = [
  httpsRedirect,
  corsConfig,
  securityHeaders,
  apiVersioning,
  requestId,
];