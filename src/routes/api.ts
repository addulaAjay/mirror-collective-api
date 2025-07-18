import { Request, Response, Router } from 'express';
import { authRoutes } from '../application/routes/auth.routes';

const router = Router();

// API Info endpoint
router.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'Mirror Collective API v1.0.0',
    description: 'RESTful API for Mirror Collective platform with comprehensive authentication',
    version: '1.0.0',
    features: [
      'User Authentication with AWS Cognito',
      'Google OAuth Integration',
      'JWT Token Management',
      'Email Services with AWS SES',
      'Rate Limiting and Security',
      'Password Reset Functionality',
    ],
    endpoints: {
      auth: '/api/auth',
      users: '/api/users',
      collections: '/api/collections',
    },
    documentation: {
      auth: '/api/auth/docs',
      health: '/api/auth/health',
    },
    timestamp: new Date().toISOString(),
  });
});

// Authentication routes
router.use('/auth', authRoutes);

// Users routes (placeholder)
router.get('/users', (req: Request, res: Response) => {
  res.json({
    message: 'Users endpoint',
    description: 'User management functionality will be available here',
    note: 'Authentication is now handled at /api/auth',
    data: [],
    count: 0,
    timestamp: new Date().toISOString(),
  });
});

// Collections routes (placeholder)
router.get('/collections', (req: Request, res: Response) => {
  res.json({
    message: 'Collections endpoint',
    description: 'Collections management functionality will be available here',
    data: [],
    count: 0,
    timestamp: new Date().toISOString(),
  });
});

export default router;
