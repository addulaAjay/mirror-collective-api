import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { EmailService } from './email.service';
import { SendEmailCommand, SESClient } from '@aws-sdk/client-ses';
import { EmailServiceError } from '../../errors/auth.errors';

vi.mock('@aws-sdk/client-ses');

describe('EmailService', () => {
  let emailService: EmailService;
  let mockClient: SESClient;
  let mockSend: Mock;

  beforeEach(() => {
    vi.clearAllMocks();

    mockSend = vi.fn();
    mockClient = {
      send: mockSend,
    } as any;

    (SESClient as Mock).mockImplementation(() => mockClient);

    process.env.AWS_REGION = 'us-east-1';
    process.env.AWS_ACCESS_KEY_ID = 'test-access-key';
    process.env.AWS_SECRET_ACCESS_KEY = 'test-secret-key';
    process.env.SES_FROM_EMAIL = 'test@example.com';

    emailService = new EmailService();
  });

  describe('constructor', () => {
    it('should initialize with environment variables', () => {
      expect(emailService).toBeInstanceOf(EmailService);
      expect(SESClient).toHaveBeenCalledWith({
        region: 'us-east-1',
        credentials: {
          accessKeyId: 'test-access-key',
          secretAccessKey: 'test-secret-key',
        },
      });
    });

    it('should use SES_REGION when available', () => {
      process.env.SES_REGION = 'us-west-2';
      new EmailService();

      expect(SESClient).toHaveBeenCalledWith(
        expect.objectContaining({
          region: 'us-west-2',
        })
      );
    });

    it('should use default from email when not provided', () => {
      delete process.env.SES_FROM_EMAIL;
      const service = new EmailService();
      expect(service).toBeInstanceOf(EmailService);
    });

    it('should use default region when not provided', () => {
      delete process.env.SES_REGION;
      delete process.env.AWS_REGION;
      new EmailService();

      expect(SESClient).toHaveBeenCalledWith(
        expect.objectContaining({
          region: 'us-east-1',
        })
      );
    });
  });

  describe('sendPasswordResetEmail', () => {
    it('should send password reset email successfully', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendPasswordResetEmail('user@example.com', '123456', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should include user name and reset code in email content', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendPasswordResetEmail('user@example.com', '123456', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      
      // Test the private methods directly to verify content generation
      const service = emailService as any;
      const htmlContent = service.generatePasswordResetEmailHtml('John', '123456');
      const textContent = service.generatePasswordResetEmailText('John', '123456');
      
      expect(htmlContent).toContain('John');
      expect(htmlContent).toContain('123456');
      expect(textContent).toContain('John');
      expect(textContent).toContain('123456');
    });

    it('should handle SES errors', async () => {
      const error = new Error('SES error');
      mockSend.mockRejectedValue(error);

      await expect(
        emailService.sendPasswordResetEmail('user@example.com', '123456', 'John')
      ).rejects.toThrow(EmailServiceError);
    });
  });

  describe('sendWelcomeEmail', () => {
    it('should send welcome email successfully', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendWelcomeEmail('user@example.com', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should include user name in welcome email content', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendWelcomeEmail('user@example.com', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      
      // Test the private methods directly to verify content generation
      const service = emailService as any;
      const htmlContent = service.generateWelcomeEmailHtml('John');
      const textContent = service.generateWelcomeEmailText('John');
      
      expect(htmlContent).toContain('John');
      expect(htmlContent).toContain('Welcome to Mirror Collective');
      expect(textContent).toContain('John');
      expect(textContent).toContain('Welcome to Mirror Collective');
    });

    it('should handle SES errors', async () => {
      const error = new Error('SES error');
      mockSend.mockRejectedValue(error);

      await expect(emailService.sendWelcomeEmail('user@example.com', 'John')).rejects.toThrow(
        EmailServiceError
      );
    });
  });

  describe('sendEmailVerificationEmail', () => {
    it('should send email verification successfully', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendEmailVerificationEmail('user@example.com', 'ABC123', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should include user name and verification code in email content', async () => {
      mockSend.mockResolvedValue({});

      await emailService.sendEmailVerificationEmail('user@example.com', 'ABC123', 'John');

      expect(mockSend).toHaveBeenCalledWith(expect.any(SendEmailCommand));
      
      // Test the private methods directly to verify content generation
      const service = emailService as any;
      const htmlContent = service.generateEmailVerificationHtml('John', 'ABC123');
      const textContent = service.generateEmailVerificationText('John', 'ABC123');
      
      expect(htmlContent).toContain('John');
      expect(htmlContent).toContain('ABC123');
      expect(textContent).toContain('John');
      expect(textContent).toContain('ABC123');
    });

    it('should handle SES errors', async () => {
      const error = new Error('SES error');
      mockSend.mockRejectedValue(error);

      await expect(
        emailService.sendEmailVerificationEmail('user@example.com', 'ABC123', 'John')
      ).rejects.toThrow(EmailServiceError);
    });
  });

  describe('generatePasswordResetEmailHtml', () => {
    it('should generate HTML with user name and reset code', () => {
      const service = emailService as any;
      const html = service.generatePasswordResetEmailHtml('John', '123456');

      expect(html).toContain('John');
      expect(html).toContain('123456');
      expect(html).toContain('Reset Your Password');
      expect(html).toContain('Mirror Collective');
      expect(html).toContain('<!DOCTYPE html>');
    });
  });

  describe('generatePasswordResetEmailText', () => {
    it('should generate text with user name and reset code', () => {
      const service = emailService as any;
      const text = service.generatePasswordResetEmailText('John', '123456');

      expect(text).toContain('John');
      expect(text).toContain('123456');
      expect(text).toContain('Reset Your Password');
      expect(text).toContain('Mirror Collective');
    });
  });

  describe('generateWelcomeEmailHtml', () => {
    it('should generate HTML with user name', () => {
      const service = emailService as any;
      const html = service.generateWelcomeEmailHtml('John');

      expect(html).toContain('John');
      expect(html).toContain('Welcome to Mirror Collective');
      expect(html).toContain('<!DOCTYPE html>');
    });
  });

  describe('generateWelcomeEmailText', () => {
    it('should generate text with user name', () => {
      const service = emailService as any;
      const text = service.generateWelcomeEmailText('John');

      expect(text).toContain('John');
      expect(text).toContain('Welcome to Mirror Collective');
    });
  });

  describe('generateEmailVerificationHtml', () => {
    it('should generate HTML with user name and verification code', () => {
      const service = emailService as any;
      const html = service.generateEmailVerificationHtml('John', 'ABC123');

      expect(html).toContain('John');
      expect(html).toContain('ABC123');
      expect(html).toContain('Verify Your Email');
      expect(html).toContain('Mirror Collective');
      expect(html).toContain('<!DOCTYPE html>');
    });
  });

  describe('generateEmailVerificationText', () => {
    it('should generate text with user name and verification code', () => {
      const service = emailService as any;
      const text = service.generateEmailVerificationText('John', 'ABC123');

      expect(text).toContain('John');
      expect(text).toContain('ABC123');
      expect(text).toContain('Verify Your Email');
      expect(text).toContain('Mirror Collective');
    });
  });
});