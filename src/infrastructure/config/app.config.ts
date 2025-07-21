import Joi from 'joi';

export interface AwsConfig {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface CognitoConfig {
  userPoolId: string;
  clientId: string;
  clientSecret: string;
}

export interface JwtConfig {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiresIn: string;
  refreshTokenExpiresIn: string;
}

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface EmailConfig {
  fromEmail: string;
  sesRegion?: string;
}

export interface AppConfig {
  port: number;
  nodeEnv: string;
  apiBaseUrl: string;
  aws: AwsConfig;
  cognito: CognitoConfig;
  jwt: JwtConfig;
  googleOAuth: GoogleOAuthConfig;
  email: EmailConfig;
  openAiApiKey: string;
}

const configSchema = Joi.object({
  port: Joi.number().port().default(3000),
  nodeEnv: Joi.string()
    .valid('development', 'staging', 'production', 'test')
    .default('development'),
  apiBaseUrl: Joi.string().uri().default('http://localhost:3000'),
  openAiApiKey: Joi.string()
    .min(32) // keys are long—optional but helps
    .required()
    .messages({
      'any.required': 'OPENAI_API_KEY is required',
      'string.empty': 'OPENAI_API_KEY cannot be empty',
    }),
  aws: Joi.object({
    region: Joi.string().required(),
    accessKeyId: Joi.string().required(),
    secretAccessKey: Joi.string().required(),
  }).required(),
  cognito: Joi.object({
    userPoolId: Joi.string().required(),
    clientId: Joi.string().required(),
    clientSecret: Joi.string().required(),
  }).required(),
  jwt: Joi.object({
    accessTokenSecret: Joi.string().min(32).required(),
    refreshTokenSecret: Joi.string().min(32).required(),
    accessTokenExpiresIn: Joi.string().default('15m'),
    refreshTokenExpiresIn: Joi.string().default('7d'),
  }).required(),
  googleOAuth: Joi.object({
    clientId: Joi.string().required(),
    clientSecret: Joi.string().required(),
    redirectUri: Joi.string().uri().required(),
  }).required(),
  email: Joi.object({
    fromEmail: Joi.string().email().required(),
    sesRegion: Joi.string().optional(),
  }).required(),
});

export function loadConfig(): AppConfig {
  const rawConfig = {
    port: parseInt(process.env.PORT || '3000', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
    apiBaseUrl: process.env.API_BASE_URL || 'http://localhost:3000',
    openAiApiKey: process.env.OPENAI_API_KEY || '',
    aws: {
      region: process.env.AWS_REGION!,
      accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    },
    cognito: {
      userPoolId: process.env.COGNITO_USER_POOL_ID!,
      clientId: process.env.COGNITO_CLIENT_ID!,
      clientSecret: process.env.COGNITO_CLIENT_SECRET!,
    },
    jwt: {
      accessTokenSecret: process.env.JWT_SECRET!,
      refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
      accessTokenExpiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m',
      refreshTokenExpiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d',
    },
    googleOAuth: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: process.env.GOOGLE_REDIRECT_URI!,
    },
    email: {
      fromEmail: process.env.SES_FROM_EMAIL!,
      sesRegion: process.env.SES_REGION,
    },
  };

  const { error, value } = configSchema.validate(rawConfig, {
    abortEarly: false,
    allowUnknown: false,
  });

  if (error) {
    const errorMessage = error.details.map((detail) => detail.message).join('\n');
    throw new Error(`Configuration validation failed:\n${errorMessage}`);
  }

  return value as AppConfig;
}

export function validateConfiguration(): { isValid: boolean; errors: string[] } {
  try {
    loadConfig();
    return { isValid: true, errors: [] };
  } catch (error: any) {
    return {
      isValid: false,
      errors: error.message.split('\n').filter((line: string) => line.trim()),
    };
  }
}