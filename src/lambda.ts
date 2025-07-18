import serverless from 'serverless-http';
import App from './app';

// Create the Express app instance
const app = new App();

// Configure for serverless environment
const isServerless = process.env.AWS_LAMBDA_FUNCTION_NAME !== undefined;

if (isServerless) {
  // Lambda-specific configuration
  console.log('Running in AWS Lambda environment');
} else {
  // Local development configuration
  console.log('Running in local development environment');
}

// Export the serverless handler
export const handler = serverless(app.app, {
  binary: ['image/*', 'application/pdf', 'application/octet-stream'],
  request: (request: any, event: any, context: any) => {
    // Add Lambda context to request for potential use in routes
    request.serverless = {
      event,
      context,
    };
  },
});

// Export app for local development
export { app };

// For local testing without serverless-offline
if (!isServerless && require.main === module) {
  const port = process.env.PORT || 3000;
  app.app.listen(port, () => {
    console.log(`🚀 Mirror Collective API running locally on port ${port}`);
  });
}
