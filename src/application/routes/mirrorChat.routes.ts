import { NextFunction, Request, Response, Router } from 'express';
import { validateMirrorChat } from '../../validators/chat.validators';
import { createMirrorChatController } from '../../infrastructure/container/controller-factory';
import { MirrorChatController } from '../controllers/mirrorChat.controller';
import { enhancedAuthenticateJWT } from '../../middleware/enhanced-auth.middleware';
import { requireAnyPermission } from '../../middleware/jwt-auth.middleware';
import { Permission } from '../../types/auth.types';
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

// Protected chat route - requires authentication and chat permissions (rate limiting temporarily disabled)
router.post(
  '/mirror',
  enhancedAuthenticateJWT,
  requireAnyPermission([Permission.CHAT_BASIC, Permission.CHAT_PREMIUM, Permission.CHAT_UNLIMITED]),
  validateMirrorChat,
  (req: Request, res: Response, next: NextFunction) => {
    getMirrorController().handleChat(req, res, next);
  }
);

export { router as mirrorChatRoutes };
