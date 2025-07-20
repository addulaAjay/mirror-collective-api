import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Configuration
import { loadConfig, validateConfiguration } from './infrastructure/config';

// Dependency injection setup
import { registerServices } from './infrastructure/container/service-registry';

// Register services immediately
registerServices();
console.log('✅ Services registered in DI container');

// Routes
import { authRoutes } from './application/routes/auth.routes';

// Error handling
import { errorHandler } from './middleware/error.middleware';

export function createApp(): express.Application {
  // Load and validate configuration
  const config = loadConfig();
  console.log('✅ Configuration loaded successfully');

  // Services already registered at module level

  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(
    cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
    })
  );

  // Rate limiting
  const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes default
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // 100 requests per window default
    message: {
      error: 'Too many requests',
      message: 'Too many requests from this IP, please try again later.',
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    // Skip rate limiting in development for localhost
    skip: (req) => {
      if (process.env.NODE_ENV === 'development') {
        const isLocalhost =
          req.ip === '::1' || req.ip === '127.0.0.1' || req.ip?.includes('localhost');
        return isLocalhost || false;
      }
      return false;
    },
  });
  app.use('/api/', limiter);

  // Logging
  if (config.nodeEnv !== 'test') {
    app.use(morgan('combined'));
  }

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Health check endpoint
  app.get('/health', (_, res) => {
    const configValidation = validateConfiguration();

    res.status(configValidation.isValid ? 200 : 503).json({
      status: configValidation.isValid ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'Mirror Collective API',
      version: '1.0.0',
      environment: config.nodeEnv,
      configuration: configValidation,
    });
  });

  // API routes
  app.use('/api/auth', authRoutes);

  // Default route
  app.get('/', (_, res) => {
    res.json({
      message: 'Mirror Collective API',
      version: '1.0.0',
      documentation: '/api/auth/docs',
      health: '/health',
    });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      error: 'Route not found',
      message: `The requested route ${req.originalUrl} was not found on this server.`,
    });
  });

  // Error handling middleware (must be last)
  app.use(errorHandler);

  return app;
}

class App {
  public app: express.Application;
  private port: number;

  constructor() {
    this.app = createApp();
    this.port = parseInt(process.env.PORT || '3000');
  }

  public listen(): void {
    this.app.listen(this.port, () => {
      console.log(`🚀 Mirror Collective API is running on port ${this.port}`);
      console.log(`📖 API Documentation available at http://localhost:${this.port}/api/auth/docs`);
      console.log(`❤️  Health check at http://localhost:${this.port}/health`);
    });
  }
}

export default App;
