import { QuizAnswersUseCase } from '@/domain/use-cases/quiz-answers.use-case';
import { NextFunction, Request, Response } from 'express';

export class QuizAnswersController {
  constructor(private useCase: QuizAnswersUseCase) {}

  async handleSubmit(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await this.useCase.execute(req.body);
      res.status(200).json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  }
}
