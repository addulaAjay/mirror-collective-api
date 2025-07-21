import { z, ZodError } from 'zod';
import type { NextFunction, Request, Response,  } from 'express';

export const mirrorChatSchema = z.object({
  message: z.string(),
  conversationHistory: z
    .array(
      z.object({
        role:    z.enum(['system','user','assistant']),
        content: z.string(),
      })
    )
    .optional(),
});


export function validateMirrorChat(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // this throws if invalid
    mirrorChatSchema.parse(req.body);
    return next();
  } catch (err) {
    if (err instanceof ZodError) {
      // map Zod errors however you like
      const errors = err.errors.map(e => ({
        field:   e.path.join('.'),
        message: e.message,
      }));
      return res.status(400).json({ success: false, errors });
    }
    // unexpected error
    return next(err);
  }
}
