import { container, TOKENS } from './container';
import { CognitoAuthRepository } from '../repositories/cognito-auth.repository';
import { JwtTokenService } from '../repositories/jwt-token.repository';
import { SesEmailService } from '../repositories/ses-email.repository';
import { GoogleOAuthRepository } from '../repositories/google-oauth.repository';
import { MirrorChatUseCase } from '../../domain/use-cases/mirror-chat.use-case';
import { OpenAIService } from '../../services/openai';

export function registerServices(): void {
  // Register repository implementations as singletons
  container.registerSingleton(TOKENS.AUTH_REPOSITORY, () => new CognitoAuthRepository());
  container.registerSingleton(TOKENS.TOKEN_SERVICE, () => new JwtTokenService());
  container.registerSingleton(TOKENS.EMAIL_SERVICE, () => new SesEmailService());
  container.registerSingleton(TOKENS.OAUTH_SERVICE, () => new GoogleOAuthRepository());
  container.registerSingleton(TOKENS.CHAT_SERVICE, () => new OpenAIService());
  container.registerSingleton(
    TOKENS.MIRROR_CHAT_USE_CASE,
    () => new MirrorChatUseCase(container.resolve(TOKENS.CHAT_SERVICE))
  );
}

export function registerTestServices(): void {
  // For testing, we can register mock implementations
  // This will be useful for unit tests
}