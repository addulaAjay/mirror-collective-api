import { container, TOKENS } from './container';
import { AuthController } from '../../application/controllers/auth.controller';
import {
  ConfirmEmailUseCase,
  ConfirmPasswordResetUseCase,
  GoogleOAuthCallbackUseCase,
  InitiatePasswordResetUseCase,
  LoginUserUseCase,
  RefreshTokenUseCase,
  RegisterUserUseCase,
  ResendVerificationCodeUseCase,
} from '../../domain/use-cases';
import { IAuthRepository, IEmailService, IOAuthService } from '../../domain/repositories';
import { MirrorChatController } from '../../application/controllers/mirrorChat.controller';
import { MirrorChatUseCase } from '../../domain/use-cases/mirror-chat.use-case';

export function createAuthController(): AuthController {
  // Resolve dependencies from container
  const authRepository = container.resolve<IAuthRepository>(TOKENS.AUTH_REPOSITORY);
  const emailService = container.resolve<IEmailService>(TOKENS.EMAIL_SERVICE);
  const oauthService = container.resolve<IOAuthService>(TOKENS.OAUTH_SERVICE);

  // Create use cases
  const registerUserUseCase = new RegisterUserUseCase(authRepository);
  const loginUserUseCase = new LoginUserUseCase(authRepository);
  const initiatePasswordResetUseCase = new InitiatePasswordResetUseCase(authRepository);
  const confirmPasswordResetUseCase = new ConfirmPasswordResetUseCase(authRepository);
  const refreshTokenUseCase = new RefreshTokenUseCase(authRepository);
  const googleOAuthCallbackUseCase = new GoogleOAuthCallbackUseCase(
    oauthService,
    authRepository,
    emailService
  );
  const confirmEmailUseCase = new ConfirmEmailUseCase(authRepository);
  const resendVerificationCodeUseCase = new ResendVerificationCodeUseCase(authRepository);

  // Create and return controller
  return new AuthController(
    registerUserUseCase,
    loginUserUseCase,
    initiatePasswordResetUseCase,
    confirmPasswordResetUseCase,
    refreshTokenUseCase,
    googleOAuthCallbackUseCase,
    confirmEmailUseCase,
    resendVerificationCodeUseCase,
    authRepository,
    oauthService
  );
}

export function createMirrorChatController(): MirrorChatController {
  const mirrorChatUseCase = container.resolve<MirrorChatUseCase>(TOKENS.MIRROR_CHAT_USE_CASE);
  return new MirrorChatController(mirrorChatUseCase);
}
