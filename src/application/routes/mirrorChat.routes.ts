import { NextFunction, Request, Response, Router } from 'express';
import { validateMirrorChat } from '../../validators/chat.validators';
import { createMirrorChatController } from '../../infrastructure/container/controller-factory';

const router = Router();

// Create controller instance
const mirrorController = createMirrorChatController();

// Main mirror route
router.post('/mirror', validateMirrorChat, (req: Request, res: Response, next: NextFunction) => {
  mirrorController.handleChat(req, res, next);
});

export { router as mirrorChatRoutes };
