import { container, TOKENS } from './container';
import { AuthController } from '../../application/controllers/auth.controller';
import {
  ConfirmPasswordResetUseCase,
  GoogleOAuthCallbackUseCase,
  InitiatePasswordResetUseCase,
  LoginUserUseCase,
  RefreshTokenUseCase,
  RegisterUserUseCase,
} from '../../domain/use-cases';
import {
  IAuthRepository,
  IEmailService,
  IOAuthService,
  ITokenService,
} from '../../domain/repositories';
import { MirrorChatController } from '../../application/controllers/mirrorChat.controller';
import { MirrorChatUseCase } from '../../domain/use-cases/mirror-chat.use-case';

export function createAuthController(): AuthController {
  // Resolve dependencies from container
  const authRepository = container.resolve<IAuthRepository>(TOKENS.AUTH_REPOSITORY);
  const tokenService = container.resolve<ITokenService>(TOKENS.TOKEN_SERVICE);
  const emailService = container.resolve<IEmailService>(TOKENS.EMAIL_SERVICE);
  const oauthService = container.resolve<IOAuthService>(TOKENS.OAUTH_SERVICE);

  // Create use cases
  const registerUserUseCase = new RegisterUserUseCase(authRepository, emailService);
  const loginUserUseCase = new LoginUserUseCase(authRepository, tokenService);
  const initiatePasswordResetUseCase = new InitiatePasswordResetUseCase(authRepository);
  const confirmPasswordResetUseCase = new ConfirmPasswordResetUseCase(authRepository);
  const refreshTokenUseCase = new RefreshTokenUseCase(tokenService, authRepository);
  const googleOAuthCallbackUseCase = new GoogleOAuthCallbackUseCase(
    oauthService,
    authRepository,
    tokenService,
    emailService
  );

  // Create and return controller
  return new AuthController(
    registerUserUseCase,
    loginUserUseCase,
    initiatePasswordResetUseCase,
    confirmPasswordResetUseCase,
    refreshTokenUseCase,
    googleOAuthCallbackUseCase,
    authRepository,
    oauthService
  );
}

export function createMirrorChatController(): MirrorChatController {
  const mirrorChatUseCase = container.resolve<MirrorChatUseCase>(TOKENS.MIRROR_CHAT_USE_CASE);
  return new MirrorChatController(mirrorChatUseCase);
}
