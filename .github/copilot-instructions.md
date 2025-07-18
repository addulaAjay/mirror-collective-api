<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Mirror Collective API - Copilot Instructions

## Project Overview

This is a TypeScript Node.js REST API project for the Mirror Collective platform. The API uses Express.js framework with modern development practices.

## Architecture & Patterns

- **Framework**: Express.js with TypeScript
- **Architecture**: RESTful API with modular routing
- **Error Handling**: Centralized error handling middleware
- **Security**: Helmet for security headers, CORS configuration
- **Logging**: Morgan for HTTP request logging
- **Environment**: dotenv for environment variable management

## Clean Code Practices

### Naming Conventions

- Use **descriptive and meaningful names** for variables, functions, and classes
- Use **camelCase** for variables and functions: `getUserById`, `isAuthenticated`
- Use **PascalCase** for classes and interfaces: `UserService`, `ApiResponse`
- Use **UPPER_SNAKE_CASE** for constants: `MAX_RETRY_ATTEMPTS`, `DEFAULT_PORT`
- Avoid abbreviations and single-letter variables (except for loops)
- Use **intention-revealing names**: `userRepository` instead of `repo`

### Function Design

- **Single Responsibility**: Each function should do one thing well
- **Small functions**: Keep functions under 20 lines when possible
- **Pure functions**: Prefer functions without side effects
- **Descriptive parameters**: Use object parameters for functions with 3+ arguments
- **Return early**: Use guard clauses to reduce nesting
- **Async/await**: Always use async/await instead of callbacks or .then()

### Code Organization

- **Separation of Concerns**: Keep business logic separate from HTTP concerns
- **Dependency Injection**: Pass dependencies as parameters rather than importing them directly
- **Single Level of Abstraction**: Keep each function at one level of abstraction
- **Consistent indentation**: Use 2 spaces (enforced by Prettier)
- **Group related code**: Put related functions and classes together

### Error Handling

- **Explicit error handling**: Always handle errors explicitly with try-catch
- **Meaningful error messages**: Include context about what went wrong
- **Error types**: Create custom error classes for different error scenarios
- **Fail fast**: Validate inputs early and throw meaningful errors
- **Don't ignore errors**: Always handle or propagate errors appropriately

### TypeScript Best Practices

- **Strict mode enabled**: Use TypeScript strict mode for better type safety
- **Explicit types**: Define explicit types for function parameters and return values
- **Interface over type**: Prefer interfaces for object shapes
- **Avoid `any`**: Never use `any` type; use `unknown` if necessary
- **Null safety**: Handle nullable values explicitly with proper type guards

### Code Documentation

- **JSDoc comments**: Document all public functions and classes
- **README updates**: Keep README.md current with setup and usage instructions
- **Inline comments**: Explain complex business logic, not obvious code
- **API documentation**: Document all endpoints with expected inputs/outputs

### Performance & Security

- **Input validation**: Validate all inputs at API boundaries
- **Rate limiting**: Implement appropriate rate limiting for endpoints
- **Sanitization**: Sanitize user inputs to prevent injection attacks
- **Minimal dependencies**: Only include necessary dependencies
- **Environment variables**: Never hardcode secrets or configuration

### Testing Practices

- **Test naming**: Use descriptive test names that explain the scenario
- **AAA pattern**: Arrange, Act, Assert structure for tests
- **Mock external dependencies**: Mock HTTP calls, databases, etc.
- **Test edge cases**: Include tests for error conditions and edge cases
- **Coverage**: Maintain high test coverage for critical business logic

## API Structure

- `/api` - Main API routes
- `/health` - Health check endpoint
- `/api/users` - User management endpoints
- `/api/auth` - Authentication endpoints
- `/api/collections` - Collections management

## Dependencies

- **Runtime**: express, cors, helmet, morgan, dotenv
- **Development**: typescript, nodemon, ts-node, eslint, prettier
- **Types**: @types/node, @types/express, @types/cors, @types/morgan

## Development Practices

### Code Quality

- Use environment variables for configuration
- Implement proper TypeScript types for all functions and variables
- Follow the established project structure in src/ directory
- Use the provided npm scripts for development (npm run dev, npm run build)
- Ensure all new routes are properly typed and documented
- Follow the existing error handling patterns

### Git & Version Control

- **Meaningful commit messages**: Use conventional commit format
- **Small commits**: Make atomic commits that represent single changes
- **Branch naming**: Use descriptive branch names like `feature/user-authentication`
- **Code reviews**: Always review code before merging

### File Organization

- **Feature-based structure**: Group files by feature rather than type
- **Index files**: Use index.ts files to create clean import paths
- **Consistent naming**: Use consistent file naming conventions
- **Single export**: Prefer default exports for main functionality

### Code Examples

```typescript
// ✅ Good: Descriptive naming and clear structure
interface UserRegistrationRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

async function registerNewUser(userData: UserRegistrationRequest): Promise<UserResponse> {
  try {
    await validateUserRegistration(userData);
    const hashedPassword = await hashPassword(userData.password);
    const user = await userRepository.create({
      email: userData.email,
      password: hashedPassword,
    });
    return formatUserResponse(user);
  } catch (error) {
    throw new UserRegistrationError(`Failed to register user: ${error.message}`);
  }
}

// ❌ Bad: Unclear naming and poor structure
async function reg(data: any) {
  const u = await db.create(data);
  return u;
}
```

### API Design Principles

- **RESTful conventions**: Use proper HTTP methods and status codes
- **Consistent response format**: Standardize API response structure
- **Pagination**: Implement pagination for list endpoints
- **Versioning**: Use API versioning for breaking changes
- **Documentation**: Maintain up-to-date API documentation
