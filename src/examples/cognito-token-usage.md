# Cognito Token Invalidation Usage Examples

## How to Use the Cognito Token Invalidation System

### 1. Setup Required Cognito Custom Attributes

Add these custom attributes to your Cognito User Pool:

```json
{
  "custom:last_logout": {
    "AttributeDataType": "String",
    "Required": false,
    "Mutable": true
  },
  "custom:logout_reason": {
    "AttributeDataType": "String", 
    "Required": false,
    "Mutable": true
  }
}
```

### 2. Using in Auth Controller for Logout

```typescript
import { AuthHelpers } from '../utils/auth-helpers';

export class AuthController {
  async logout(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      
      if (userId) {
        // This will invalidate all tokens for the user
        await AuthHelpers.handleUserLogout(
          userId,
          'user_logout',
          req.ip,
          req.headers['user-agent'],
          req.requestId
        );
      }

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Logout failed',
        message: 'Unable to complete logout process'
      });
    }
  }

  // Logout all devices/sessions
  async logoutAllDevices(req: Request, res: Response): Promise<void> {
    const userId = req.user?.id;
    
    if (userId) {
      await AuthHelpers.handleUserLogout(
        userId,
        'logout_all_devices',
        req.ip,
        req.headers['user-agent'],
        req.requestId
      );
    }

    res.json({ success: true });
  }

  // Security-related token invalidation
  async changePassword(req: Request, res: Response): Promise<void> {
    const userId = req.user?.id;
    
    // ... password change logic ...
    
    // Invalidate all tokens for security
    if (userId) {
      await AuthHelpers.handleSecurityLogout(
        userId,
        'password_change',
        req.ip,
        req.headers['user-agent'],
        req.requestId
      );
    }

    res.json({ 
      success: true,
      message: 'Password changed. Please log in again with your new password.'
    });
  }
}
```

### 3. How Token Validation Works

1. **User logs in** → Cognito issues JWT with current timestamp
2. **User logs out** → `custom:last_logout` is updated in Cognito to current timestamp
3. **Subsequent requests** → Middleware checks if token was issued before logout time
4. **If token is old** → Request is rejected with 401

### 4. Security Benefits

- ✅ **No external database required** - uses existing Cognito
- ✅ **Immediate effect** - tokens invalid across all instances  
- ✅ **Persistent** - logout time stored in Cognito permanently
- ✅ **Audit trail** - all logout events are logged
- ✅ **Granular control** - different logout reasons tracked

### 5. Testing the Implementation

```typescript
// Test token invalidation
const testTokenInvalidation = async () => {
  // 1. User logs in and gets token
  const loginResponse = await fetch('/api/auth/login', { ... });
  const { accessToken } = loginResponse.data.tokens;

  // 2. Use token - should work
  const profileResponse = await fetch('/api/auth/me', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  console.log('Before logout:', profileResponse.status); // 200

  // 3. Logout
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  // 4. Try to use same token - should fail
  const retryResponse = await fetch('/api/auth/me', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  console.log('After logout:', retryResponse.status); // 401
};
```

### 6. Environment Variables Required

```bash
# Required for Cognito Token Invalidation
COGNITO_USER_POOL_ID=your-user-pool-id
AWS_REGION=your-aws-region

# AWS credentials (via IAM role or environment)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 7. Monitoring & Analytics

The system provides built-in analytics:

```typescript
const tokenInvalidationService = new CognitoTokenInvalidationService();

// Get logout statistics
const stats = await tokenInvalidationService.getInvalidationStats(userProfiles);
console.log({
  totalUsers: stats.totalUsers,
  usersWithLogouts: stats.usersWithLogouts,
  recentLogouts: stats.recentLogouts
});
```

This implementation provides robust token invalidation without requiring Redis or a database!