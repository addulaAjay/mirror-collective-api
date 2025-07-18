import { SendEmailCommand, SESClient } from '@aws-sdk/client-ses';
import { EmailServiceError } from '../../errors/auth.errors';

/**
 * AWS SES email service for sending authentication-related emails
 */
export class EmailService {
  private client: SESClient;
  private fromEmail: string;

  constructor() {
    this.client = new SESClient({
      region: process.env.SES_REGION || process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
      },
    });

    this.fromEmail = process.env.SES_FROM_EMAIL || 'noreply@yourdomain.com';
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(
    toEmail: string,
    resetCode: string,
    firstName: string
  ): Promise<void> {
    try {
      const subject = 'Reset Your Password - Mirror Collective';
      const htmlBody = this.generatePasswordResetEmailHtml(firstName, resetCode);
      const textBody = this.generatePasswordResetEmailText(firstName, resetCode);

      const command = new SendEmailCommand({
        Source: this.fromEmail,
        Destination: {
          ToAddresses: [toEmail],
        },
        Message: {
          Subject: {
            Data: subject,
            Charset: 'UTF-8',
          },
          Body: {
            Html: {
              Data: htmlBody,
              Charset: 'UTF-8',
            },
            Text: {
              Data: textBody,
              Charset: 'UTF-8',
            },
          },
        },
      });

      await this.client.send(command);
      console.log(`Password reset email sent to ${toEmail}`);
    } catch (error: any) {
      console.error('Error sending password reset email:', error);
      throw new EmailServiceError(`Failed to send password reset email: ${error.message}`);
    }
  }

  /**
   * Send welcome email to new users
   */
  async sendWelcomeEmail(toEmail: string, firstName: string): Promise<void> {
    try {
      const subject = 'Welcome to Mirror Collective!';
      const htmlBody = this.generateWelcomeEmailHtml(firstName);
      const textBody = this.generateWelcomeEmailText(firstName);

      const command = new SendEmailCommand({
        Source: this.fromEmail,
        Destination: {
          ToAddresses: [toEmail],
        },
        Message: {
          Subject: {
            Data: subject,
            Charset: 'UTF-8',
          },
          Body: {
            Html: {
              Data: htmlBody,
              Charset: 'UTF-8',
            },
            Text: {
              Data: textBody,
              Charset: 'UTF-8',
            },
          },
        },
      });

      await this.client.send(command);
      console.log(`Welcome email sent to ${toEmail}`);
    } catch (error: any) {
      console.error('Error sending welcome email:', error);
      throw new EmailServiceError(`Failed to send welcome email: ${error.message}`);
    }
  }

  /**
   * Send email verification email
   */
  async sendEmailVerificationEmail(
    toEmail: string,
    verificationCode: string,
    firstName: string
  ): Promise<void> {
    try {
      const subject = 'Verify Your Email - Mirror Collective';
      const htmlBody = this.generateEmailVerificationHtml(firstName, verificationCode);
      const textBody = this.generateEmailVerificationText(firstName, verificationCode);

      const command = new SendEmailCommand({
        Source: this.fromEmail,
        Destination: {
          ToAddresses: [toEmail],
        },
        Message: {
          Subject: {
            Data: subject,
            Charset: 'UTF-8',
          },
          Body: {
            Html: {
              Data: htmlBody,
              Charset: 'UTF-8',
            },
            Text: {
              Data: textBody,
              Charset: 'UTF-8',
            },
          },
        },
      });

      await this.client.send(command);
      console.log(`Email verification sent to ${toEmail}`);
    } catch (error: any) {
      console.error('Error sending email verification:', error);
      throw new EmailServiceError(`Failed to send email verification: ${error.message}`);
    }
  }

  /**
   * Generate HTML content for password reset email
   */
  private generatePasswordResetEmailHtml(firstName: string, resetCode: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background-color: #ffffff; padding: 30px; border: 1px solid #dee2e6; }
          .footer { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; font-size: 12px; }
          .reset-code { background-color: #e9ecef; padding: 15px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; border-radius: 4px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Mirror Collective</h1>
          </div>
          <div class="content">
            <h2>Reset Your Password</h2>
            <p>Hello ${firstName},</p>
            <p>We received a request to reset your password. Use the code below to reset your password:</p>
            <div class="reset-code">${resetCode}</div>
            <p>This code will expire in 15 minutes for security reasons.</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
            <p>Best regards,<br>The Mirror Collective Team</p>
          </div>
          <div class="footer">
            <p>© 2025 Mirror Collective. All rights reserved.</p>
            <p>This is an automated email. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate text content for password reset email
   */
  private generatePasswordResetEmailText(firstName: string, resetCode: string): string {
    return `
Reset Your Password - Mirror Collective

Hello ${firstName},

We received a request to reset your password. Use the code below to reset your password:

Reset Code: ${resetCode}

This code will expire in 15 minutes for security reasons.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Best regards,
The Mirror Collective Team

© 2025 Mirror Collective. All rights reserved.
This is an automated email. Please do not reply to this email.
    `.trim();
  }

  /**
   * Generate HTML content for welcome email
   */
  private generateWelcomeEmailHtml(firstName: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Mirror Collective</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background-color: #ffffff; padding: 30px; border: 1px solid #dee2e6; }
          .footer { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; font-size: 12px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Mirror Collective</h1>
          </div>
          <div class="content">
            <h2>Welcome to Mirror Collective!</h2>
            <p>Hello ${firstName},</p>
            <p>Welcome to Mirror Collective! We're excited to have you join our community.</p>
            <p>Your account has been successfully created and you can now start exploring all the features we have to offer.</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
            <p>Best regards,<br>The Mirror Collective Team</p>
          </div>
          <div class="footer">
            <p>© 2025 Mirror Collective. All rights reserved.</p>
            <p>This is an automated email. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate text content for welcome email
   */
  private generateWelcomeEmailText(firstName: string): string {
    return `
Welcome to Mirror Collective!

Hello ${firstName},

Welcome to Mirror Collective! We're excited to have you join our community.

Your account has been successfully created and you can now start exploring all the features we have to offer.

If you have any questions or need assistance, please don't hesitate to contact our support team.

Best regards,
The Mirror Collective Team

© 2025 Mirror Collective. All rights reserved.
This is an automated email. Please do not reply to this email.
    `.trim();
  }

  /**
   * Generate HTML content for email verification
   */
  private generateEmailVerificationHtml(firstName: string, verificationCode: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background-color: #ffffff; padding: 30px; border: 1px solid #dee2e6; }
          .footer { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; font-size: 12px; }
          .verification-code { background-color: #e9ecef; padding: 15px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Mirror Collective</h1>
          </div>
          <div class="content">
            <h2>Verify Your Email Address</h2>
            <p>Hello ${firstName},</p>
            <p>Thank you for registering with Mirror Collective! Please verify your email address using the code below:</p>
            <div class="verification-code">${verificationCode}</div>
            <p>This verification code will expire in 24 hours.</p>
            <p>If you didn't create an account with us, please ignore this email.</p>
            <p>Best regards,<br>The Mirror Collective Team</p>
          </div>
          <div class="footer">
            <p>© 2025 Mirror Collective. All rights reserved.</p>
            <p>This is an automated email. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate text content for email verification
   */
  private generateEmailVerificationText(firstName: string, verificationCode: string): string {
    return `
Verify Your Email Address - Mirror Collective

Hello ${firstName},

Thank you for registering with Mirror Collective! Please verify your email address using the code below:

Verification Code: ${verificationCode}

This verification code will expire in 24 hours.

If you didn't create an account with us, please ignore this email.

Best regards,
The Mirror Collective Team

© 2025 Mirror Collective. All rights reserved.
This is an automated email. Please do not reply to this email.
    `.trim();
  }
}
