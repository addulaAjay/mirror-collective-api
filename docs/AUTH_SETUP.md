# Authentication API Setup Guide

This document provides step-by-step instructions for setting up the Mirror Collective Authentication API with AWS Cognito and Google OAuth integration.

## Prerequisites

- Node.js 18+ installed
- AWS Account with appropriate permissions
- Google Cloud Console account
- Domain name (for production email configuration)

## 1. Install Dependencies

```bash
npm install
```

## 2. Environment Configuration

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Update the `.env` file with your actual configuration values (see sections below).

## 3. AWS Services Setup

### 3.1 AWS Cognito User Pool

1. **Create User Pool:**

```bash
aws cognito-idp create-user-pool \
    --pool-name "MirrorCollectiveUserPool" \
    --policies PasswordPolicy='{MinimumLength=8,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}' \
    --auto-verified-attributes email \
    --username-attributes email \
    --schema Name=email,AttributeDataType=String,Required=true Name=given_name,AttributeDataType=String,Required=true Name=family_name,AttributeDataType=String,Required=true
```

2. **Create User Pool Client:**

```bash
aws cognito-idp create-user-pool-client \
    --user-pool-id "us-east-1_xxxxxxxxx" \
    --client-name "MirrorCollectiveClient" \
    --explicit-auth-flows ADMIN_NO_SRP_AUTH USER_PASSWORD_AUTH \
    --generate-secret
```

3. **Update your .env file with:**

```bash
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret
```

### 3.2 AWS SES Configuration

1. **Verify your sending email address:**

```bash
aws ses verify-email-identity --email-address noreply@yourdomain.com
```

2. **Create email templates:**

```bash
# Password Reset Template
aws ses create-template \
    --template '{
        "TemplateName": "PasswordReset",
        "Subject": "Reset Your Password - Mirror Collective",
        "HtmlPart": "<h1>Reset Your Password</h1><p>Your reset code is: {{code}}</p>",
        "TextPart": "Your password reset code is: {{code}}"
    }'

# Welcome Email Template
aws ses create-template \
    --template '{
        "TemplateName": "Welcome",
        "Subject": "Welcome to Mirror Collective!",
        "HtmlPart": "<h1>Welcome {{firstName}}!</h1><p>Thanks for joining Mirror Collective.</p>",
        "TextPart": "Welcome {{firstName}}! Thanks for joining Mirror Collective."
    }'
```

3. **Update your .env file with:**

```bash
SES_FROM_EMAIL=noreply@yourdomain.com
SES_REGION=us-east-1
```

### 3.3 IAM Role and Policies

Create an IAM policy for the application:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminInitiateAuth",
        "cognito-idp:AdminSetUserPassword",
        "cognito-idp:AdminDeleteUser",
        "cognito-idp:ForgotPassword",
        "cognito-idp:ConfirmForgotPassword",
        "cognito-idp:ListUsers",
        "ses:SendEmail",
        "ses:SendTemplatedEmail",
        "ses:VerifyEmailIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 4. Google OAuth Setup

### 4.1 Google Cloud Console

1. **Create a new project** or select existing project
2. **Enable Google+ API** (or Google People API)
3. **Create OAuth 2.0 credentials:**
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:3000/api/auth/google/callback`

4. **Update your .env file with:**

```bash
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback
```

## 5. JWT Configuration

Generate secure JWT secrets (minimum 32 characters):

```bash
# Generate random secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Update your .env file:

```bash
JWT_SECRET=your-generated-secret-here
JWT_REFRESH_SECRET=your-different-generated-secret-here
```

## 6. Complete Environment Variables

Your final `.env` file should look like this:

```bash
# Application Configuration
NODE_ENV=development
PORT=3000
API_BASE_URL=http://localhost:3000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# JWT Configuration
JWT_SECRET=your-32-char-secret-here
JWT_REFRESH_SECRET=your-different-32-char-secret
JWT_ACCESS_TOKEN_EXPIRES_IN=15m
JWT_REFRESH_TOKEN_EXPIRES_IN=7d

# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key

# AWS Cognito Configuration
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=your-cognito-client-id
COGNITO_CLIENT_SECRET=your-cognito-client-secret

# AWS SES Configuration
SES_FROM_EMAIL=noreply@yourdomain.com
SES_REGION=us-east-1

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# API Configuration
API_VERSION=v1
```

## 7. Running the Application

1. **Development mode:**

```bash
npm run dev
```

2. **Production build:**

```bash
npm run build
npm start
```

3. **Check health:**

```bash
curl http://localhost:3000/health
curl http://localhost:3000/api/auth/health
```

## 8. API Endpoints

### Authentication Endpoints

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/forgot-password` - Initiate password reset
- `POST /api/auth/reset-password` - Reset password with code
- `POST /api/auth/refresh` - Refresh access token

### Google OAuth Endpoints

- `GET /api/auth/google` - Initiate Google OAuth
- `GET /api/auth/google/callback` - OAuth callback

### Protected Endpoints

- `GET /api/auth/me` - Get current user profile
- `POST /api/auth/logout` - Logout user
- `DELETE /api/auth/account` - Delete user account

### Utility Endpoints

- `GET /api/auth/health` - Service health check
- `GET /api/auth/docs` - API documentation

## 9. Testing the API

### Register a new user:

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login:

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

### Access protected endpoint:

```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 10. Security Considerations

- **Always use HTTPS in production**
- **Rotate JWT secrets regularly**
- **Monitor rate limits and failed attempts**
- **Enable AWS CloudTrail for audit logging**
- **Use strong password policies**
- **Regularly update dependencies**

## 11. Monitoring and Logging

- Check CloudWatch logs for AWS services
- Monitor API metrics and performance
- Set up alerts for authentication failures
- Track user registration and login patterns

## 12. Deployment

For deployment instructions, see the deployment documentation in the `docs/` directory.

## 13. Troubleshooting

### Common Issues:

1. **Cognito connection errors:** Check AWS credentials and region
2. **Google OAuth errors:** Verify redirect URI configuration
3. **Email delivery issues:** Check SES configuration and sender verification
4. **JWT errors:** Ensure secrets are properly configured
5. **Rate limiting:** Adjust limits in environment variables

### Debug Mode:

Set `NODE_ENV=development` for detailed error messages.

## Support

For support or questions about the authentication API, please refer to the project documentation or contact the development team.
