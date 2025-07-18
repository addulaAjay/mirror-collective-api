# Mirror Collective API

A comprehensive RESTful API for the Mirror Collective platform built with TypeScript, Express.js, and AWS services. Features complete user authentication with AWS Cognito, Google OAuth integration, JWT token management, and email services.

## 🚀 Features

- **Complete Authentication System**
  - User registration and login
  - Password reset functionality  
  - Email verification
  - JWT token management (access & refresh tokens)

- **AWS Integration**
  - AWS Cognito for user management
  - AWS SES for email services
  - AWS Lambda ready (serverless deployment)

- **Google OAuth Support**
  - Complete OAuth 2.0 flow
  - User profile integration
  - Secure token handling

- **Security & Performance**
  - Rate limiting on authentication endpoints
  - Input validation and sanitization
  - Comprehensive error handling
  - Security headers with Helmet.js

- **Developer Experience**
  - TypeScript for type safety
  - Comprehensive API documentation
  - Health check endpoints
  - Clean code architecture

## 📋 Prerequisites

- Node.js 18+ 
- AWS Account with appropriate permissions
- Google Cloud Console account (for OAuth)
- Domain name (for production email configuration)

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd mirror_collective_api
```

2. **Install dependencies:**
```bash
npm install
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your actual configuration values
```

4. **Build the project:**
```bash
npm run build
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.example` and configure the following:

#### Application Settings
```bash
NODE_ENV=development
PORT=3000
API_BASE_URL=http://localhost:3000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

#### JWT Configuration
```bash
JWT_SECRET=your-32-character-secret
JWT_REFRESH_SECRET=your-different-32-character-secret
JWT_ACCESS_TOKEN_EXPIRES_IN=15m
JWT_REFRESH_TOKEN_EXPIRES_IN=7d
```

#### AWS Configuration
```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# Cognito
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret

# SES
SES_FROM_EMAIL=noreply@yourdomain.com
SES_REGION=us-east-1
```

#### Google OAuth
```bash
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback
```

### AWS Services Setup

For detailed setup instructions, see [Authentication Setup Guide](./docs/AUTH_SETUP.md).

## 🚀 Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm start
```

### Serverless Deployment
```bash
npm run deploy:staging
npm run deploy:production
```

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api
```

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Forgot Password
```http
POST /api/auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password
```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "email": "user@example.com",
  "resetCode": "123456",
  "newPassword": "NewSecurePassword123!"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer your-access-token
```

### Google OAuth Endpoints

#### Initiate OAuth
```http
GET /api/auth/google?state=optional-state
```

#### OAuth Callback
```http
GET /api/auth/google/callback?code=auth-code&state=state
```

### Utility Endpoints

#### API Documentation
```http
GET /api/auth/docs
```

#### Health Check
```http
GET /api/auth/health
```

#### Service Health
```http
GET /health
```

## 🔒 Rate Limiting

- **Authentication endpoints**: 5 requests per 15 minutes
- **Password reset**: 3 requests per hour  
- **General API**: 100 requests per 15 minutes

## 🧪 Testing

### Manual Testing

Test the API using curl or your preferred HTTP client:

```bash
# Health check
curl http://localhost:3000/health

# API documentation
curl http://localhost:3000/api/auth/docs

# Register user (will fail without proper AWS setup)
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Development Testing

For development without AWS setup, the API will return appropriate error messages indicating configuration requirements.

## 📁 Project Structure

```
src/
├── controllers/         # HTTP request handlers
├── errors/             # Custom error classes
├── middleware/         # Express middleware
├── routes/             # Route definitions
├── services/           # Business logic services
├── types/              # TypeScript type definitions
├── validators/         # Input validation schemas
├── app.ts              # Express application setup
├── server.ts           # HTTP server
└── lambda.ts           # AWS Lambda handler

docs/                   # Documentation
deploy.sh              # Deployment script
serverless.yml         # Serverless configuration
tsconfig.json          # TypeScript configuration
```

## 🛡️ Security Features

- **Input Validation**: Joi schema validation for all endpoints
- **Rate Limiting**: Express rate limit middleware
- **Security Headers**: Helmet.js for security headers
- **JWT Security**: Secure token generation and validation
- **CORS Configuration**: Configurable CORS policies
- **Error Handling**: Sanitized error responses

## 🚀 Deployment

### Serverless Framework

The API is configured for serverless deployment:

```bash
# Deploy to staging
npm run deploy:staging

# Deploy to production  
npm run deploy:production

# View logs
npm run logs:staging
npm run logs:production
```

### Traditional Deployment

For traditional server deployment:

1. Build the application: `npm run build`
2. Set production environment variables
3. Start the server: `npm start`

## 📊 Monitoring

- **Health Checks**: Built-in health endpoints
- **Logging**: Morgan HTTP request logging
- **Error Tracking**: Comprehensive error handling
- **AWS CloudWatch**: Integration ready for production

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Build project
npm run build
```

## 📝 License

This project is licensed under the ISC License.

## 🔗 Links

- **API Documentation**: `/api/auth/docs`
- **Health Check**: `/health`
- **Authentication Health**: `/api/auth/health`
- **Setup Guide**: [docs/AUTH_SETUP.md](./docs/AUTH_SETUP.md)
- **Deployment Guide**: [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md)

## 📞 Support

For support or questions about the API:

1. Check the [Authentication Setup Guide](./docs/AUTH_SETUP.md)
2. Review the API documentation at `/api/auth/docs`
3. Check the health endpoints for configuration issues
4. Contact the development team

---

**Mirror Collective API** - Built with ❤️ using TypeScript, Express.js, AWS Cognito, and modern development practices.
