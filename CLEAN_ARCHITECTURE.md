# Clean Architecture Implementation

## Overview

This document outlines the clean architecture refactoring implemented for the Mirror Collective API. The new architecture follows SOLID principles, implements dependency injection, and provides better separation of concerns.

## Architecture Layers

### 1. Domain Layer (`/domain`)
**Pure business logic with no external dependencies**

- **Repositories (Interfaces)**: Define contracts for data access
  - `IAuthRepository`: User authentication and management
  - `ITokenService`: JWT token operations
  - `IEmailService`: Email notifications
  - `IOAuthService`: OAuth operations

- **Use Cases**: Encapsulate business rules and orchestrate operations
  - `RegisterUserUseCase`: User registration logic
  - `LoginUserUseCase`: User authentication logic
  - `RefreshTokenUseCase`: Token refresh logic
  - `GoogleOAuthCallbackUseCase`: OAuth callback handling

### 2. Application Layer (`/application`)
**Application-specific business rules and HTTP concerns**

- **Controllers**: Handle HTTP requests/responses
  - `CleanAuthController`: Clean implementation using dependency injection

- **Routes**: Define API endpoints and middleware
  - `auth.routes.clean.ts`: Clean routes implementation

### 3. Infrastructure Layer (`/infrastructure`)
**External concerns and implementations**

- **Repositories**: Concrete implementations of domain interfaces
  - `CognitoAuthRepository`: AWS Cognito implementation
  - `JwtTokenService`: JWT token service implementation
  - `SesEmailService`: AWS SES email service
  - `GoogleOAuthRepository`: Google OAuth implementation

- **Container**: Dependency injection setup
  - `container.ts`: DI container implementation
  - `service-registry.ts`: Service registration
  - `controller-factory.ts`: Factory for creating controllers

- **Config**: Centralized configuration management
  - `app.config.ts`: Configuration schema and validation

## Key Benefits

### ✅ **SOLID Principles Compliance**

1. **Single Responsibility**: Each class has one reason to change
2. **Open/Closed**: Easy to extend without modifying existing code
3. **Liskov Substitution**: All implementations respect their interfaces
4. **Interface Segregation**: Focused, cohesive interfaces
5. **Dependency Inversion**: High-level modules don't depend on low-level modules

### ✅ **Improved Testability**
- Dependency injection enables easy mocking
- Use cases can be tested in isolation
- Repository interfaces allow for test implementations

### ✅ **Better Separation of Concerns**
- Business logic separated from infrastructure
- HTTP concerns separated from domain logic
- Configuration centralized and validated

### ✅ **Enhanced Maintainability**
- Clear boundaries between layers
- Easy to locate and modify specific functionality
- Consistent error handling across the application

## Usage Examples

### Using the Clean Architecture

```typescript
// 1. Initialize services and DI container
import { registerServices } from './infrastructure/container/service-registry';
import { createApp } from './app.clean';

registerServices();
const app = createApp();

// 2. Services are automatically injected via container
// No manual instantiation needed!
```

### Creating New Use Cases

```typescript
// domain/use-cases/new-feature.use-case.ts
export class NewFeatureUseCase {
  constructor(
    private authRepository: IAuthRepository,
    private emailService: IEmailService
  ) {}

  async execute(request: NewFeatureRequest): Promise<NewFeatureResponse> {
    // Pure business logic here
  }
}
```

### Adding New Repository Implementations

```typescript
// infrastructure/repositories/new-auth.repository.ts
export class NewAuthRepository implements IAuthRepository {
  // Implement interface methods
  async createUser(userData: CreateUserRequest): Promise<UserProfile> {
    // Your implementation here
  }
}
```

## File Structure

```
src/
├── domain/                     # Business logic (no dependencies)
│   ├── repositories/           # Interface definitions
│   │   ├── auth.repository.ts
│   │   ├── token.repository.ts
│   │   └── email.repository.ts
│   └── use-cases/              # Business use cases
│       ├── register-user.use-case.ts
│       ├── login-user.use-case.ts
│       └── refresh-token.use-case.ts
├── application/                # Application layer
│   ├── controllers/            # HTTP controllers
│   │   └── auth.controller.clean.ts
│   └── routes/                 # Route definitions
│       └── auth.routes.clean.ts
├── infrastructure/            # External concerns
│   ├── repositories/          # Concrete implementations
│   │   ├── cognito-auth.repository.ts
│   │   ├── jwt-token.repository.ts
│   │   └── ses-email.repository.ts
│   ├── container/             # Dependency injection
│   │   ├── container.ts
│   │   ├── service-registry.ts
│   │   └── controller-factory.ts
│   └── config/                # Configuration
│       └── app.config.ts
├── shared/                    # Shared utilities
│   ├── errors/                # Error definitions
│   ├── types/                 # Type definitions
│   └── validators/            # Input validation
└── app.clean.ts               # Clean app entry point
```

## Migration Strategy

### Phase 1: Gradual Migration ✅ **COMPLETED**
- ✅ Created interfaces and abstractions
- ✅ Implemented dependency injection container
- ✅ Created use cases for business logic
- ✅ Built adapter repositories for existing services
- ✅ Added centralized configuration

### Phase 2: Testing & Validation
- Add comprehensive tests for new architecture
- Validate performance and functionality
- Update existing tests to use new structure

### Phase 3: Full Migration
- Replace old controllers with clean implementations
- Update all routes to use new structure
- Remove legacy code
- Update deployment scripts

## Testing Strategy

### Unit Tests
```typescript
// Example: Testing use cases in isolation
describe('RegisterUserUseCase', () => {
  let useCase: RegisterUserUseCase;
  let mockAuthRepo: jest.Mocked<IAuthRepository>;
  let mockEmailService: jest.Mocked<IEmailService>;

  beforeEach(() => {
    mockAuthRepo = createMockAuthRepository();
    mockEmailService = createMockEmailService();
    useCase = new RegisterUserUseCase(mockAuthRepo, mockEmailService);
  });

  it('should register user successfully', async () => {
    // Test pure business logic
  });
});
```

### Integration Tests
- Test with real implementations but isolated from external services
- Use test containers for database/external service dependencies

## Configuration Management

The new architecture includes centralized, validated configuration:

```typescript
// Automatic validation on startup
const config = loadConfig();

// Type-safe access to configuration
const dbUrl = config.database.url;
const jwtSecret = config.jwt.accessTokenSecret;
```

## Error Handling

Improved error handling with:
- Consistent error response format
- Proper HTTP status codes
- Production-safe error messages
- Centralized error middleware

## Future Enhancements

1. **Event-Driven Architecture**: Add domain events for loose coupling
2. **CQRS**: Separate read/write operations for complex queries
3. **Microservices**: Easy to extract features into separate services
4. **Observability**: Add structured logging and metrics
5. **Performance**: Add caching and optimization layers

## Conclusion

The clean architecture implementation provides:
- **Better maintainability** through clear separation of concerns
- **Improved testability** via dependency injection
- **Enhanced flexibility** for future changes
- **Stronger foundation** for scaling the application

The architecture is backward-compatible and can be migrated gradually, ensuring minimal disruption to existing functionality.