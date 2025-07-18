# AWS Lambda Deployment Guide

This guide explains how to deploy the Mirror Collective API to AWS Lambda using GitHub Actions.

## Prerequisites

### 1. AWS Account Setup

- Create an AWS account if you don't have one
- Create an IAM user with programmatic access
- Attach the following AWS managed policies:
  - `AWSLambdaFullAccess`
  - `IAMFullAccess`
  - `AmazonAPIGatewayAdministrator`
  - `CloudFormationFullAccess`
  - `AmazonS3FullAccess`
  - `CloudWatchLogsFullAccess`

### 2. GitHub Secrets Configuration

Add the following secrets to your GitHub repository:

#### For Staging Environment:

- `AWS_ACCESS_KEY_ID`: Your staging AWS access key
- `AWS_SECRET_ACCESS_KEY`: Your staging AWS secret key

#### For Production Environment:

- `AWS_ACCESS_KEY_ID_PROD`: Your production AWS access key
- `AWS_SECRET_ACCESS_KEY_PROD`: Your production AWS secret key

### 3. Environment Variables Setup

Update the environment files:

- `.env.staging` - Staging environment configuration
- `.env.production` - Production environment configuration

## Deployment Process

### Automatic Deployment (Recommended)

The GitHub Actions workflow automatically deploys when:

- **Staging**: Push to `main` branch
- **Production**: Push to `production` branch

### Manual Deployment

#### Local Development with Serverless Offline:

```bash
npm run dev:serverless
```

#### Deploy to Staging:

```bash
npm run deploy:staging
```

#### Deploy to Production:

```bash
npm run deploy:production
```

## GitHub Actions Workflow

The workflow includes:

1. **Test**: Runs linting, build, and tests
2. **Deploy Staging**: Deploys to staging on main branch push
3. **Deploy Production**: Deploys to production on production branch push

### Workflow Features:

- ✅ Automated testing before deployment
- ✅ Environment-specific deployments
- ✅ Integration and smoke tests
- ✅ Deployment notifications
- ✅ Rollback capabilities

## AWS Resources Created

The deployment creates:

- **Lambda Function**: Hosts your API
- **API Gateway**: Provides HTTP endpoints
- **CloudWatch Logs**: For monitoring and debugging
- **IAM Roles**: For Lambda execution

## Monitoring and Debugging

### View Logs:

```bash
# Staging logs
npm run logs:staging

# Production logs
npm run logs:production
```

### CloudWatch Dashboard:

Access AWS CloudWatch console to monitor:

- Function invocations
- Error rates
- Duration metrics
- Memory usage

## Environment Configuration

### Required Environment Variables:

- `NODE_ENV`: Environment (staging/production)
- `ALLOWED_ORIGINS`: CORS allowed origins
- `API_VERSION`: API version

### Optional Environment Variables:

- `DATABASE_URL`: Database connection string
- `JWT_SECRET`: JWT signing secret
- `API_GATEWAY_REST_API_ID`: Existing API Gateway ID
- `RATE_LIMIT_*`: Rate limiting configuration

## Serverless Framework Commands

### Deployment:

```bash
serverless deploy --stage staging
serverless deploy --stage production
```

### Remove Stack:

```bash
npm run remove:staging
npm run remove:production
```

### Function Information:

```bash
serverless info --stage staging
```

### Invoke Function:

```bash
serverless invoke --function api --stage staging
```

## Custom Domain Setup (Optional)

To use a custom domain:

1. Purchase/configure domain in Route 53
2. Create SSL certificate in ACM
3. Uncomment domain configuration in `serverless.yml`
4. Update the certificate ARN

## Troubleshooting

### Common Issues:

1. **Cold Start Performance**:
   - Increase memory allocation in `serverless.yml`
   - Implement warming strategies for critical functions

2. **Environment Variables Not Loading**:
   - Verify GitHub secrets are set correctly
   - Check environment file configurations

3. **CORS Issues**:
   - Update `ALLOWED_ORIGINS` in environment files
   - Verify API Gateway CORS configuration

4. **Deployment Timeout**:
   - Check CloudFormation stack status in AWS console
   - Verify IAM permissions

### Debug Commands:

```bash
# Local testing
npm run dev:serverless

# Check serverless info
serverless info --stage staging

# View recent logs
serverless logs -f api --stage staging -t
```

## Security Best Practices

1. **Environment Variables**: Never commit secrets to git
2. **IAM Permissions**: Use least privilege principle
3. **API Gateway**: Enable request validation
4. **Rate Limiting**: Implement appropriate limits
5. **CORS**: Configure specific origins, not wildcards
6. **Monitoring**: Set up CloudWatch alarms

## Cost Optimization

- **Memory Allocation**: Right-size memory based on usage
- **Timeout Settings**: Set appropriate timeouts
- **Dead Letter Queues**: Handle failed invocations
- **Reserved Concurrency**: Control concurrent executions

## Support

For deployment issues:

1. Check GitHub Actions logs
2. Review CloudWatch logs
3. Verify AWS console for resource status
4. Check this documentation for troubleshooting steps
