import Joi from 'joi';

/**
 * Validation schemas for authentication endpoints
 */

// Common password validation
const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]'))
  .message(
    'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one number, and one special character'
  )
  .required();

// Email validation
const emailSchema = Joi.string()
  .email({ tlds: { allow: false } })
  .max(254)
  .required();

// Name validation
const nameSchema = Joi.string()
  .min(1)
  .max(50)
  .pattern(/^[a-zA-Z\s'-]+$/)
  .message('Name must contain only letters, spaces, hyphens, and apostrophes')
  .required();

// User registration validation schema
export const userRegistrationSchema = Joi.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: nameSchema,
  lastName: nameSchema,
});

// User login validation schema
export const userLoginSchema = Joi.object({
  email: emailSchema,
  password: Joi.string().required(),
});

// Forgot password validation schema
export const forgotPasswordSchema = Joi.object({
  email: emailSchema,
});

// Reset password validation schema
export const resetPasswordSchema = Joi.object({
  email: emailSchema,
  resetCode: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/)
    .message('Reset code must be a 6-digit number')
    .required(),
  newPassword: passwordSchema,
});

// Google OAuth callback validation schema
export const googleAuthCallbackSchema = Joi.object({
  code: Joi.string().required(),
  state: Joi.string().optional(),
});

// Refresh token validation schema
export const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

// Change password validation schema
export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: passwordSchema,
});

// Validation function helper
export const validateRequest = (
  schema: Joi.ObjectSchema,
  data: any
): { error?: string; validationErrors?: Array<{ field: string; message: string }> } => {
  const { error } = schema.validate(data, { abortEarly: false });

  if (error) {
    const validationErrors = error.details.map((detail) => ({
      field: detail.path.join('.'),
      message: detail.message,
    }));

    return {
      error: 'Validation failed',
      validationErrors,
    };
  }

  return {};
};
