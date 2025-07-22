import { NextFunction, Request, Response, Router } from 'express';
import { validateMirrorChat } from '../../validators/chat.validators';
import { createMirrorChatController } from '../../infrastructure/container/controller-factory';
import { MirrorChatController } from '../controllers/mirrorChat.controller';
import { extractCognitoUser } from '../../middleware/cognito-context.middleware';
// Rate limiting temporarily disabled - will re-enable when database is configured
// import { apiRateLimit } from '../../middleware/rate-limit.middleware';
import { applySecurity } from '../../middleware/security-headers.middleware';

const router = Router();

// Apply security middleware to all routes
router.use(applySecurity);

// Lazy controller initialization for Lambda compatibility
let mirrorController: MirrorChatController | null = null;
const getMirrorController = (): MirrorChatController => {
  if (!mirrorController) {
    mirrorController = createMirrorChatController();
  }
  return mirrorController;
};

// Protected chat route - Authentication handled by API Gateway Cognito authorizer
// Extract user context from API Gateway authorizer before processing
router.post(
  '/mirror',
  extractCognitoUser,
  validateMirrorChat,
  (req: Request, res: Response, next: NextFunction) => {
    getMirrorController().handleChat(req, res, next);
  }
);

export { router as mirrorChatRoutes };
