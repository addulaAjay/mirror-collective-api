import { MirrorChatUseCase } from '../../domain/use-cases/mirror-chat.use-case';
import { NextFunction, Request, Response } from 'express';

export class MirrorChatController {
  constructor(private useCase: MirrorChatUseCase) {}

  async handleChat(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await this.useCase.execute(req.body);
      res.status(200).json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  }
}
