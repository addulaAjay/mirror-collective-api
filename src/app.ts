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

// Routes
import { authRoutes } from './application/routes/auth.routes';

// Error handling
import { errorHandler } from './middleware/error.middleware';

export function createApp(): express.Application {
  // Load and validate configuration
  const config = loadConfig();
  console.log('✅ Configuration loaded successfully');

  // Register services in DI container
  registerServices();
  console.log('✅ Services registered in DI container');

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
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests',
      message: 'Too many requests from this IP, please try again later.',
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
  app.use('*', (req, res) => {
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
