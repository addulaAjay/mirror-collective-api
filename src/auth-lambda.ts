import serverless from 'serverless-http';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Configuration and services
import { loadConfig } from './infrastructure/config';
import { registerServices } from './infrastructure/container/service-registry';

// Auth routes only
import { authRoutes } from './application/routes/auth.routes';

// Error handling
import { errorHandler } from './middleware/error.middleware';

// Register services
registerServices();
console.log('✅ Auth Lambda services registered');

// Load configuration
const config = loadConfig();
console.log('✅ Auth Lambda configuration loaded');

// Create Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  })
);

// Rate limiting - more restrictive for auth
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '50'), // Lower limit for auth
  message: {
    error: 'Too many authentication requests',
    message: 'Too many authentication requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Logging
if (config.nodeEnv !== 'test') {
  app.use(morgan('combined'));
}

// Debug middleware to log request body
app.use((req, res, next) => {
  console.log('DEBUG: Raw request body type:', typeof req.body);
  console.log('DEBUG: Raw request body:', req.body);
  console.log('DEBUG: Request headers:', req.headers);
  console.log('DEBUG: Content-Type:', req.get('content-type'));
  next();
});

// Body parsing middleware with error handling
app.use(
  express.json({
    limit: '1mb',
    type: 'application/json',
  })
);
app.use(express.urlencoded({ extended: true }));

// JSON parsing error handler
app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (error instanceof SyntaxError && 'body' in error) {
    console.error('JSON parsing error:', error.message);
    return res.status(400).json({
      success: false,
      error: 'Invalid JSON format',
      message: 'The request body contains invalid JSON',
    });
  }
  next(error);
});

// Health check for auth lambda
app.get('/health', (_, res) => {
  res.json({
    status: 'healthy',
    service: 'Mirror Collective Auth API',
    timestamp: new Date().toISOString(),
  });
});

// Mount auth routes at /api/auth (to handle the full path)
app.use('/api/auth', authRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Auth route not found',
    message: `The requested auth route ${req.originalUrl} was not found.`,
  });
});

// Error handling middleware
app.use(errorHandler);

// Export serverless handler with proper API Gateway configuration
export const handler = serverless(app, {
  binary: false,
});
