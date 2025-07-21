import { Request, Response, Router } from 'express';
import { authRoutes } from '../application/routes/auth.routes';
import { mirrorChatRoutes } from '../application/routes/mirrorChat.routes';
import { applySecurity } from '../middleware/security-headers.middleware';
// Rate limiting temporarily disabled - will re-enable when database is configured
// import { apiRateLimit } from '../middleware/rate-limit.middleware';

const router = Router();

// Apply security middleware to all API routes
router.use(applySecurity);

// API Info endpoint (rate limiting temporarily disabled)
router.get('/', (_req: Request, res: Response) => {
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

// Chat routes
router.use('/chat', mirrorChatRoutes);

export default router;
