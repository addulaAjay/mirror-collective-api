import { container, TOKENS } from './container';
import { AuthController } from '../../application/controllers/auth.controller';
import {
  RegisterUserUseCase,
  LoginUserUseCase,
  InitiatePasswordResetUseCase,
  ConfirmPasswordResetUseCase,
  RefreshTokenUseCase,
  GoogleOAuthCallbackUseCase,
} from '../../domain/use-cases';
import {
  IAuthRepository,
  ITokenService,
  IEmailService,
  IOAuthService,
} from '../../domain/repositories';

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
