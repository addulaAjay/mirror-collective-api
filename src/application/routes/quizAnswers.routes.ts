import { NextFunction, Request, Response, Router } from 'express';
import { createQuizAnswersController } from '../../infrastructure/container/controller-factory';
const router = Router();
// Create controller instance
const quizAnswersController = createQuizAnswersController();

// Main quiz answers route
router.post('/submit', (req: Request, res: Response, next: NextFunction) => {
    console.log('Quiz answers submission request received', req.body);
    quizAnswersController.handleSubmit(req, res, next);
});

export { router as quizAnswersRoutes };
