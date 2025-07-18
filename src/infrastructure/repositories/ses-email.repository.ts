import { IEmailService } from '../../domain/repositories/email.repository';
import { EmailService } from '../../services';

export class SesEmailService implements IEmailService {
  private emailService: EmailService;

  constructor() {
    this.emailService = new EmailService();
  }

  async sendPasswordResetEmail(toEmail: string, resetCode: string, firstName: string): Promise<void> {
    return this.emailService.sendPasswordResetEmail(toEmail, resetCode, firstName);
  }

  async sendWelcomeEmail(toEmail: string, firstName: string): Promise<void> {
    return this.emailService.sendWelcomeEmail(toEmail, firstName);
  }

  async sendEmailVerificationEmail(toEmail: string, verificationCode: string, firstName: string): Promise<void> {
    return this.emailService.sendEmailVerificationEmail(toEmail, verificationCode, firstName);
  }
}