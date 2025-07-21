import { vi } from 'vitest';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.AWS_REGION = 'us-east-1';
process.env.AWS_ACCESS_KEY_ID = 'test-access-key';
process.env.AWS_SECRET_ACCESS_KEY = 'test-secret-key';
process.env.COGNITO_USER_POOL_ID = 'us-east-1_testpool';
process.env.COGNITO_CLIENT_ID = 'test-client-id';
process.env.COGNITO_CLIENT_SECRET = 'test-client-secret';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-purposes-only';
process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-key-for-testing-purposes-only';
process.env.JWT_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/api/auth/google/callback';
process.env.SES_FROM_EMAIL = 'test@example.com';
process.env.API_BASE_URL = 'http://localhost:3000';
process.env.OPENAI_API_KEY = 'test-openai-key-that-is-long-enough-123456';

// Global test mocks
vi.mock('aws-sdk', () => ({
  CognitoIdentityServiceProvider: vi.fn(() => ({
    adminCreateUser: vi.fn(),
    adminGetUser: vi.fn(),
    adminDeleteUser: vi.fn(),
    adminInitiateAuth: vi.fn(),
    forgotPassword: vi.fn(),
    confirmForgotPassword: vi.fn(),
  })),
  SES: vi.fn(() => ({
    sendEmail: vi.fn(),
  })),
}));

vi.mock('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: vi.fn(() => ({})),
  AdminCreateUserCommand: vi.fn(),
  AdminGetUserCommand: vi.fn(),
  AdminDeleteUserCommand: vi.fn(),
  AdminInitiateAuthCommand: vi.fn(),
  ForgotPasswordCommand: vi.fn(),
  ConfirmForgotPasswordCommand: vi.fn(),
}));

vi.mock('@aws-sdk/client-ses', () => ({
  SESClient: vi.fn(() => ({})),
  SendEmailCommand: vi.fn(),
}));

vi.mock('googleapis', () => ({
  google: {
    auth: {
      OAuth2: vi.fn(() => ({
        generateAuthUrl: vi.fn(),
        getToken: vi.fn(),
        setCredentials: vi.fn(),
      })),
    },
    oauth2: vi.fn(() => ({
      userinfo: {
        get: vi.fn(),
      },
    })),
  },
}));

vi.mock('openai', () => {
  return {
    OpenAI: class {
      createChatCompletion = vi.fn();
      createImage = vi.fn();
    },
  };
});

// Console mocks to reduce noise in tests
global.console = {
  ...console,
  log: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
};

import { registerServices } from './infrastructure/container/service-registry';
registerServices();