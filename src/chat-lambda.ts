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

// Body parsing middleware - larger limit for chat data
app.use(express.json({ limit: '5mb' })); // Larger for conversation history
app.use(express.urlencoded({ extended: true }));

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

// Export serverless handler
export const handler = serverless(app);
