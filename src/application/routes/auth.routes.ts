import { NextFunction, Request, Response, Router } from 'express';
import { createAuthController } from '../../infrastructure/container/controller-factory';
import { authMiddleware } from '../../middleware/auth.middleware';
import {
  forgotPasswordSchema,
  refreshTokenSchema,
  resetPasswordSchema,
  userLoginSchema,
  userRegistrationSchema,
  validateRequest,
} from '../../validators/auth.validators';

const router = Router();

// Create controller instance
const authController = createAuthController();

// Generic validation middleware factory
const createValidationMiddleware =
  (schema: any) =>
  (req: Request, res: Response, next: NextFunction): void => {
    const { error, validationErrors } = validateRequest(schema, req.body);
    if (error) {
      res.status(400).json({ success: false, error, validationErrors });
      return;
    }
    next();
  };

// Validation middleware instances
const validateRegistration = createValidationMiddleware(userRegistrationSchema);
const validateLogin = createValidationMiddleware(userLoginSchema);
const validateForgotPassword = createValidationMiddleware(forgotPasswordSchema);
const validateResetPassword = createValidationMiddleware(resetPasswordSchema);
const validateRefreshToken = createValidationMiddleware(refreshTokenSchema);

// Routes
router.post('/register', validateRegistration, authController.register);
router.post('/login', validateLogin, authController.login);
router.post('/forgot-password', validateForgotPassword, authController.forgotPassword);
router.post('/reset-password', validateResetPassword, authController.resetPassword);
router.post('/refresh', validateRefreshToken, authController.refreshToken);

// OAuth routes
router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

// Protected routes
router.get('/me', authMiddleware, authController.getCurrentUser);
router.post('/logout', authMiddleware, authController.logout);
router.delete('/account', authMiddleware, authController.deleteAccount);

export { router as authRoutes };
