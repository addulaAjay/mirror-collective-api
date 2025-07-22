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
  email: Joi.object({
    fromEmail: Joi.string().email().allow('').optional(),
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
      region: process.env.AWS_REGION || '',
      accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
    },
    cognito: {
      userPoolId: process.env.COGNITO_USER_POOL_ID || '',
      clientId: process.env.COGNITO_CLIENT_ID || '',
      clientSecret: process.env.COGNITO_CLIENT_SECRET || '',
    },
    email: {
      fromEmail: process.env.SES_FROM_EMAIL || '',
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
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown configuration error';
    return {
      isValid: false,
      errors: errorMessage.split('\n').filter((line: string) => line.trim()),
    };
  }
}
