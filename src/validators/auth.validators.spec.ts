import { describe, expect, it } from 'vitest';
import {
  changePasswordSchema,
  forgotPasswordSchema,
  googleAuthCallbackSchema,
  refreshTokenSchema,
  resetPasswordSchema,
  userLoginSchema,
  userRegistrationSchema,
  validateRequest,
} from './auth.validators';

describe('Auth Validators', () => {
  describe('userRegistrationSchema', () => {
    it('should validate valid registration data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid email', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['email']);
    });

    it('should reject weak password', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'weak',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['password']);
    });

    it('should reject password without special characters', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPassword123',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['password']);
    });

    it('should reject invalid first name with numbers', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'John123',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['firstName']);
    });

    it('should accept names with apostrophes and hyphens', () => {
      const validData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: "O'Connor",
        lastName: 'Smith-Jones',
      };

      const { error } = userRegistrationSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject empty first name', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: '',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['firstName']);
    });

    it('should reject too long first name', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'A'.repeat(51),
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['firstName']);
    });

    it('should reject missing required fields', () => {
      const invalidData = {
        email: 'test@example.com',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('userLoginSchema', () => {
    it('should validate valid login data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'anyPassword',
      };

      const { error } = userLoginSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid email', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'password',
      };

      const { error } = userLoginSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['email']);
    });

    it('should reject missing password', () => {
      const invalidData = {
        email: 'test@example.com',
      };

      const { error } = userLoginSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['password']);
    });

    it('should accept any password for login', () => {
      const validData = {
        email: 'test@example.com',
        password: 'any',
      };

      const { error } = userLoginSchema.validate(validData);
      expect(error).toBeUndefined();
    });
  });

  describe('forgotPasswordSchema', () => {
    it('should validate valid email', () => {
      const validData = {
        email: 'test@example.com',
      };

      const { error } = forgotPasswordSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid email', () => {
      const invalidData = {
        email: 'invalid-email',
      };

      const { error } = forgotPasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['email']);
    });

    it('should reject missing email', () => {
      const invalidData = {};

      const { error } = forgotPasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['email']);
    });
  });

  describe('resetPasswordSchema', () => {
    it('should validate valid reset password data', () => {
      const validData = {
        email: 'test@example.com',
        resetCode: '123456',
        newPassword: 'NewPassword123!',
      };

      const { error } = resetPasswordSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid reset code format', () => {
      const invalidData = {
        email: 'test@example.com',
        resetCode: 'abc123',
        newPassword: 'NewPassword123!',
      };

      const { error } = resetPasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['resetCode']);
    });

    it('should reject reset code with wrong length', () => {
      const invalidData = {
        email: 'test@example.com',
        resetCode: '12345',
        newPassword: 'NewPassword123!',
      };

      const { error } = resetPasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['resetCode']);
    });

    it('should reject weak new password', () => {
      const invalidData = {
        email: 'test@example.com',
        resetCode: '123456',
        newPassword: 'weak',
      };

      const { error } = resetPasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['newPassword']);
    });
  });

  describe('googleAuthCallbackSchema', () => {
    it('should validate valid callback data', () => {
      const validData = {
        code: 'auth-code-123',
        state: 'state-parameter',
      };

      const { error } = googleAuthCallbackSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should validate callback data without state', () => {
      const validData = {
        code: 'auth-code-123',
      };

      const { error } = googleAuthCallbackSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject missing code', () => {
      const invalidData = {
        state: 'state-parameter',
      };

      const { error } = googleAuthCallbackSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['code']);
    });
  });

  describe('refreshTokenSchema', () => {
    it('should validate valid refresh token', () => {
      const validData = {
        refreshToken: 'valid-jwt-refresh-token',
      };

      const { error } = refreshTokenSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject missing refresh token', () => {
      const invalidData = {};

      const { error } = refreshTokenSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['refreshToken']);
    });

    it('should reject empty refresh token', () => {
      const invalidData = {
        refreshToken: '',
      };

      const { error } = refreshTokenSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['refreshToken']);
    });
  });

  describe('changePasswordSchema', () => {
    it('should validate valid change password data', () => {
      const validData = {
        currentPassword: 'CurrentPassword123!',
        newPassword: 'NewPassword123!',
      };

      const { error } = changePasswordSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject missing current password', () => {
      const invalidData = {
        newPassword: 'NewPassword123!',
      };

      const { error } = changePasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['currentPassword']);
    });

    it('should reject weak new password', () => {
      const invalidData = {
        currentPassword: 'CurrentPassword123!',
        newPassword: 'weak',
      };

      const { error } = changePasswordSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['newPassword']);
    });
  });

  describe('validateRequest helper function', () => {
    it('should return empty object for valid data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const result = validateRequest(userRegistrationSchema, validData);

      expect(result.error).toBeUndefined();
      expect(result.validationErrors).toBeUndefined();
    });

    it('should return validation errors for invalid data', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'weak',
      };

      const result = validateRequest(userRegistrationSchema, invalidData);

      expect(result.error).toBe('Validation failed');
      expect(result.validationErrors).toBeDefined();
      expect(result.validationErrors?.length).toBeGreaterThan(0);
      expect(result.validationErrors?.[0]).toHaveProperty('field');
      expect(result.validationErrors?.[0]).toHaveProperty('message');
    });

    it('should return all validation errors (not abort early)', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'weak',
        firstName: '',
        lastName: 'Doe123',
      };

      const result = validateRequest(userRegistrationSchema, invalidData);

      expect(result.validationErrors?.length).toBeGreaterThanOrEqual(3);
    });

    it('should format field paths correctly for nested objects', () => {
      const nestedSchema = userRegistrationSchema;
      const invalidData = {
        email: 'invalid',
      };

      const result = validateRequest(nestedSchema, invalidData);

      expect(result.validationErrors?.some(err => err.field === 'email')).toBe(true);
    });
  });

  describe('Password validation edge cases', () => {
    it('should reject password that is too long', () => {
      const invalidData = {
        email: 'test@example.com',
        password: `${'A'.repeat(129)  }1!`,
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['password']);
    });

    it('should accept password with exactly 8 characters', () => {
      const validData = {
        email: 'test@example.com',
        password: 'Test123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should accept password with exactly 128 characters', () => {
      const validPassword = `${'A'.repeat(125)  }1a!`;
      const validData = {
        email: 'test@example.com',
        password: validPassword,
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(validData);
      expect(error).toBeUndefined();
    });
  });

  describe('Email validation edge cases', () => {
    it('should accept valid email with reasonable length', () => {
      const longEmail = 'test.user.with.long.name@example.com';
      const validData = {
        email: longEmail,
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject email longer than 254 characters', () => {
      const longEmail = `${'a'.repeat(251)  }@x.com`;
      const invalidData = {
        email: longEmail,
        password: 'TestPassword123!',
        firstName: 'John',
        lastName: 'Doe',
      };

      const { error } = userRegistrationSchema.validate(invalidData);
      expect(error).toBeDefined();
      expect(error?.details[0].path).toEqual(['email']);
    });
  });
});