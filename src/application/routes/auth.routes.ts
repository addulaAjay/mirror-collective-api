import { NextFunction, Request, Response, Router } from 'express';
import Joi from 'joi';
import { createAuthController } from '../../infrastructure/container/controller-factory';
import { extractCognitoUser } from '../../middleware/cognito-context.middleware';
import { AuthController } from '../controllers/auth.controller';
import {
  emailVerificationSchema,
  forgotPasswordSchema,
  refreshTokenSchema,
  resendVerificationCodeSchema,
  resetPasswordSchema,
  userLoginSchema,
  userRegistrationSchema,
  validateRequest,
} from '../../validators/auth.validators';
// Rate limiting temporarily disabled - will re-enable when database is configured
// import {
//   apiRateLimit,
//   authRateLimit,
//   failedLoginTracker,
//   passwordResetRateLimit,
// } from '../../middleware/rate-limit.middleware';
import { applySecurity } from '../../middleware/security-headers.middleware';

const router = Router();

// Apply security middleware to all routes
router.use(applySecurity);

// Lazy controller initialization for Lambda compatibility
let authController: AuthController | null = null;
const getAuthController = (): AuthController => {
  if (!authController) {
    authController = createAuthController();
  }
  return authController;
};

// Generic validation middleware factory
const createValidationMiddleware =
  (schema: Joi.ObjectSchema) =>
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
const validateEmailVerification = createValidationMiddleware(emailVerificationSchema);
const validateResendVerificationCode = createValidationMiddleware(resendVerificationCodeSchema);

// Routes (rate limiting temporarily disabled)
router.post('/register', validateRegistration, (req, res, next) =>
  getAuthController().register(req, res, next)
);
router.post('/login', validateLogin, (req, res, next) => getAuthController().login(req, res, next));
router.post('/forgot-password', validateForgotPassword, (req, res, next) =>
  getAuthController().forgotPassword(req, res, next)
);
router.post('/reset-password', validateResetPassword, (req, res, next) =>
  getAuthController().resetPassword(req, res, next)
);
router.post('/refresh', validateRefreshToken, (req, res, next) =>
  getAuthController().refreshToken(req, res, next)
);
router.post('/confirm-email', validateEmailVerification, (req, res, next) =>
  getAuthController().confirmEmail(req, res, next)
);
router.post('/resend-verification-code', validateResendVerificationCode, (req, res, next) =>
  getAuthController().resendVerificationCode(req, res, next)
);

// OAuth routes
// router.get('/google', (req, res, next) => getAuthController().googleAuth(req, res, next));
// router.get('/google/callback', (req, res, next) => getAuthController().googleCallback(req, res, next));

// Protected routes - Authentication handled by API Gateway Cognito authorizer
// Extract user context from API Gateway authorizer before processing
router.get('/me', extractCognitoUser, (req, res, next) =>
  getAuthController().getCurrentUser(req, res, next)
);
router.post('/logout', extractCognitoUser, (req, res, next) =>
  getAuthController().logout(req, res, next)
);
router.delete('/account', extractCognitoUser, (req, res, next) =>
  getAuthController().deleteAccount(req, res, next)
);

export { router as authRoutes };
