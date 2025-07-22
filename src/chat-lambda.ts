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

// Chat routes only
import { mirrorChatRoutes } from './application/routes/mirrorChat.routes';

// Error handling
import { errorHandler } from './middleware/error.middleware';

// Register services
registerServices();
console.log('✅ Chat Lambda services registered');

// Load configuration
const config = loadConfig();
console.log('✅ Chat Lambda configuration loaded');

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

// Rate limiting - optimized for AI chat workloads
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '30'), // Lower for AI processing
  message: {
    error: 'Too many chat requests',
    message: 'Too many chat requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Logging
if (config.nodeEnv !== 'test') {
  app.use(morgan('combined'));
}

// Body parsing middleware with error handling
app.use(
  express.json({
    limit: '5mb', // Larger for conversation history
    type: 'application/json',
  })
);
app.use(express.urlencoded({ extended: true }));

// Debug middleware to log parsed request body
app.use((req, _, next) => {
  console.log('DEBUG Chat Lambda: Parsed request body type:', typeof req.body);
  console.log('DEBUG Chat Lambda: Parsed request body:', req.body);
  console.log('DEBUG Chat Lambda: Request headers:', req.headers);
  console.log('DEBUG Chat Lambda: Content-Type:', req.get('content-type'));
  console.log('DEBUG Chat Lambda: Request path:', req.path);
  console.log('DEBUG Chat Lambda: Request method:', req.method);
  console.log('DEBUG Chat Lambda: Authorization header:', req.get('Authorization'));
  next();
});

// JSON parsing error handler
app.use((error: Error, _: express.Request, res: express.Response, next: express.NextFunction) => {
  if (error instanceof SyntaxError && 'body' in error) {
    console.error('JSON parsing error:', error.message);
    res.status(400).json({
      success: false,
      error: 'Invalid JSON format',
      message: 'The request body contains invalid JSON',
    });
    return;
  }
  return next(error);
});

// Health check for chat lambda
app.get('/health', (_, res) => {
  res.json({
    status: 'healthy',
    service: 'Mirror Collective Chat API',
    timestamp: new Date().toISOString(),
  });
});

// Mount chat routes at /api/chat (to handle the full path)
app.use('/api/chat', mirrorChatRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Chat route not found',
    message: `The requested chat route ${req.originalUrl} was not found.`,
  });
});

// Error handling middleware
app.use(errorHandler);

// API Gateway event interface
interface ApiGatewayEvent {
  body?: string | null;
  headers: { [key: string]: string };
  multiValueHeaders: { [key: string]: string[] };
  httpMethod: string;
  isBase64Encoded: boolean;
  path: string;
  pathParameters: { [key: string]: string } | null;
  queryStringParameters: { [key: string]: string } | null;
  multiValueQueryStringParameters: { [key: string]: string[] } | null;
  stageVariables: { [key: string]: string } | null;
  requestContext: {
    accountId: string;
    apiId: string;
    protocol: string;
    httpMethod: string;
    path: string;
    stage: string;
    requestId: string;
    requestTime: string;
    requestTimeEpoch: number;
    identity: {
      cognitoIdentityPoolId: string | null;
      accountId: string | null;
      cognitoIdentityId: string | null;
      caller: string | null;
      sourceIp: string;
      principalOrgId: string | null;
      accessKey: string | null;
      cognitoAuthenticationType: string | null;
      cognitoAuthenticationProvider: string | null;
      userArn: string | null;
      userAgent: string;
      user: string | null;
    };
    authorizer?: {
      claims?: { [key: string]: string };
      [key: string]: unknown;
    } & { [key: string]: unknown };
  };
  resource: string;
  [key: string]: unknown;
}

// Extended request interface for serverless
interface ServerlessRequest {
  body?: unknown;
  [key: string]: unknown;
}

export const handler = serverless(app, {
  binary: false,
  request: (req: ServerlessRequest, event: ApiGatewayEvent, _unused: unknown) => {
    // Ensure proper JSON parsing for API Gateway
    if (event.body && typeof event.body === 'string') {
      try {
        req.body = JSON.parse(event.body);
        console.log('✅ Chat Lambda: Successfully parsed JSON body from API Gateway event');
      } catch (error) {
        console.error('❌ Chat Lambda: Failed to parse JSON body:', error);
      }
    }
  },
});
