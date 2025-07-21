import { Router } from 'express';
import { validateMirrorChat }         from '../../validators/chat.validators';
import { createMirrorChatController } from '../../infrastructure/container/controller-factory';

const router = Router();
const mirrorController = createMirrorChatController();
router.post('/mirror-chat', validateMirrorChat, mirrorController.handleChat.bind(mirrorController));

export { router as mirrorChatRoutes };
