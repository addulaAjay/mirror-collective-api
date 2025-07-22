export type ServiceToken = string | symbol;

export interface Container {
  register<T>(token: ServiceToken, factory: () => T): void;
  registerSingleton<T>(token: ServiceToken, factory: () => T): void;
  resolve<T>(token: ServiceToken): T;
  isRegistered(token: ServiceToken): boolean;
}

class DIContainer implements Container {
  private services = new Map<ServiceToken, () => any>();
  private singletons = new Map<ServiceToken, any>();

  register<T>(token: ServiceToken, factory: () => T): void {
    this.services.set(token, factory);
  }

  registerSingleton<T>(token: ServiceToken, factory: () => T): void {
    this.services.set(token, () => {
      if (!this.singletons.has(token)) {
        this.singletons.set(token, factory());
      }
      return this.singletons.get(token);
    });
  }

  resolve<T>(token: ServiceToken): T {
    const factory = this.services.get(token);
    if (!factory) {
      throw new Error(`Service not registered: ${String(token)}`);
    }
    return factory();
  }

  isRegistered(token: ServiceToken): boolean {
    return this.services.has(token);
  }

  clear(): void {
    this.services.clear();
    this.singletons.clear();
  }
}

export const container = new DIContainer();

// Service tokens
export const TOKENS = {
  AUTH_REPOSITORY: Symbol('AuthRepository'),
  EMAIL_SERVICE: Symbol('EmailService'),
  OAUTH_SERVICE: Symbol('OAuthService'),
  CHAT_SERVICE: Symbol('ChatService'),
  MIRROR_CHAT_USE_CASE: Symbol('MirrorChatUseCase'),
  AUDIT_LOG_SERVICE: Symbol('AuditLogService'),
  TOKEN_BLACKLIST_SERVICE: Symbol('TokenBlacklistService'),
  TOKEN_INVALIDATION_SERVICE: Symbol('TokenInvalidationService'),
} as const;

export type ServiceTokens = typeof TOKENS;
