#!/bin/bash

# Deployment script for Mirror Collective API
# Usage: ./deploy.sh [staging|production|local]

set -e

STAGE=${1:-staging}
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Mirror Collective API to ${STAGE}...${NC}"

# Validate stage
if [[ ! "$STAGE" =~ ^(staging|production|local)$ ]]; then
    echo -e "${RED}❌ Invalid stage: $STAGE. Use 'staging', 'production', or 'local'${NC}"
    exit 1
fi

# Check if required tools are installed
if ! command -v serverless &> /dev/null; then
    echo -e "${YELLOW}⚠️  Serverless Framework not found. Installing...${NC}"
    npm install -g serverless
fi

# Build the application
echo -e "${YELLOW}📦 Building application...${NC}"
npm run build

if [ "$STAGE" = "local" ]; then
    echo -e "${GREEN}🏠 Starting local development server...${NC}"
    npm run dev:serverless
else
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials not configured. Please run 'aws configure' first.${NC}"
        exit 1
    fi

    # Deploy to AWS
    echo -e "${YELLOW}☁️  Deploying to AWS Lambda (${STAGE})...${NC}"
    serverless deploy --stage $STAGE

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Deployment successful!${NC}"
        echo -e "${GREEN}📊 Getting deployment info...${NC}"
        serverless info --stage $STAGE
        
        # Test the health endpoint
        if command -v curl &> /dev/null; then
            echo -e "${YELLOW}🔍 Testing health endpoint...${NC}"
            API_URL=$(serverless info --stage $STAGE | grep "endpoints:" -A 1 | tail -1 | awk '{print $2}')
            if [ ! -z "$API_URL" ]; then
                curl -s "${API_URL}/health" | jq . || echo "Health check response received"
            fi
        fi
    else
        echo -e "${RED}❌ Deployment failed!${NC}"
        exit 1
    fi
fi
