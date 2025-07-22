import { container, TOKENS } from './container';
import { CognitoAuthRepository } from '../repositories/cognito-auth.repository';
import { SesEmailService } from '../repositories/ses-email.repository';
import { GoogleOAuthRepository } from '../repositories/google-oauth.repository';
import { MirrorChatUseCase } from '../../domain/use-cases/mirror-chat.use-case';
import { OpenAIService } from '../../services/openai';
import { AuditLogService } from '../../services/security/audit-log.service';
import { TokenBlacklistService } from '../../services/security/token-blacklist.service';
import { CognitoTokenInvalidationService } from '../../services/security/cognito-token-invalidation.service';

export function registerServices(): void {
  // Register repository implementations as singletons
  container.registerSingleton(TOKENS.AUTH_REPOSITORY, () => new CognitoAuthRepository());
  container.registerSingleton(TOKENS.EMAIL_SERVICE, () => new SesEmailService());
  container.registerSingleton(TOKENS.OAUTH_SERVICE, () => new GoogleOAuthRepository());
  container.registerSingleton(TOKENS.CHAT_SERVICE, () => new OpenAIService());
  container.registerSingleton(TOKENS.AUDIT_LOG_SERVICE, () => new AuditLogService());
  container.registerSingleton(TOKENS.TOKEN_BLACKLIST_SERVICE, () => new TokenBlacklistService());
  container.registerSingleton(
    TOKENS.TOKEN_INVALIDATION_SERVICE,
    () => new CognitoTokenInvalidationService()
  );
  container.registerSingleton(
    TOKENS.MIRROR_CHAT_USE_CASE,
    () => new MirrorChatUseCase(container.resolve(TOKENS.CHAT_SERVICE))
  );
}

export function registerTestServices(): void {
  // For testing, we can register mock implementations
  // This will be useful for unit tests
}
