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

// Full name validation
const fullNameSchema = Joi.string()
  .min(2)
  .max(100)
  .pattern(/^[a-zA-Z\s'-]+$/)
  .message('Full name must contain only letters, spaces, hyphens, and apostrophes')
  .required();

// User registration validation schema
export const userRegistrationSchema = Joi.object({
  email: emailSchema,
  password: passwordSchema,
  fullName: fullNameSchema,
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


// Refresh token validation schema
export const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

// Email verification validation schema
export const emailVerificationSchema = Joi.object({
  email: emailSchema,
  code: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/)
    .message('Verification code must be a 6-digit number')
    .required(),
});

// Resend verification code validation schema
export const resendVerificationCodeSchema = Joi.object({
  email: emailSchema,
});

// Change password validation schema
export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: passwordSchema,
});

// Validation function helper
export const validateRequest = (
  schema: Joi.ObjectSchema,
  data: unknown
): { error?: string; validationErrors?: Array<{ field: string; message: string }> } => {
  // Debug logging
  console.log('🔍 Validation input data:', JSON.stringify(data));
  console.log('🔍 Validation input type:', typeof data);
  console.log('🔍 Validation input constructor:', data?.constructor?.name);

  // Handle edge case where data might be null, undefined, or not an object
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    console.log('❌ Invalid request body format - not an object');
    return {
      error: 'Validation failed',
      validationErrors: [
        {
          field: 'body',
          message: 'Request body must be a valid JSON object',
        },
      ],
    };
  }

  const { error } = schema.validate(data, { abortEarly: false });

  if (error) {
    console.log('❌ Validation error:', error.details);
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
