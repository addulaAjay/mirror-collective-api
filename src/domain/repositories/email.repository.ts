export interface IEmailService {
  sendPasswordResetEmail(toEmail: string, resetCode: string, firstName: string): Promise<void>;
  sendWelcomeEmail(toEmail: string, firstName: string): Promise<void>;
  sendEmailVerificationEmail(toEmail: string, verificationCode: string, firstName: string): Promise<void>;
}