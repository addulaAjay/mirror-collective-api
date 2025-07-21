import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { CognitoJwtPayload, Permission, UserPermissions, UserRole } from '../../types/auth.types';
import { AuthenticationError } from '../../errors/auth.errors';

/**
 * Cognito JWT verification service
 */
export class CognitoJwtService {
  private jwksClient: jwksClient.JwksClient;
  private userPoolId: string;
  private region: string;
  private issuer: string;

  constructor() {
    this.userPoolId = process.env.COGNITO_USER_POOL_ID || '';
    this.region = process.env.AWS_REGION || 'us-east-1';
    this.issuer = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`;

    if (!this.userPoolId) {
      throw new Error('COGNITO_USER_POOL_ID environment variable is required');
    }

    // Initialize JWKS client to verify JWT signatures
    this.jwksClient = jwksClient({
      jwksUri: `${this.issuer}/.well-known/jwks.json`,
      cache: true,
      cacheMaxAge: 600000, // 10 minutes
      cacheMaxEntries: 5,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
    });
  }

  /**
   * Get signing key from Cognito JWKS
   */
  private getSigningKey = (header: jwt.JwtHeader): Promise<string> => {
    return new Promise((resolve, reject) => {
      const kid = header.kid;
      if (!kid) {
        reject(new Error('Token header missing key ID'));
        return;
      }

      this.jwksClient.getSigningKey(kid, (err: Error | null, key?: jwksClient.SigningKey) => {
        if (err) {
          reject(err);
        } else {
          const signingKey = key?.getPublicKey();
          if (signingKey) {
            resolve(signingKey);
          } else {
            reject(new Error('Unable to get signing key'));
          }
        }
      });
    });
  };

  /**
   * Verify Cognito JWT token
   */
  async verifyToken(token: string): Promise<CognitoJwtPayload> {
    return new Promise((resolve, reject) => {
      // Decode header to get key ID
      const decodedHeader = jwt.decode(token, { complete: true });
      console.log('Decoded JWT Header:', decodedHeader);
      if (!decodedHeader || !decodedHeader.header.kid) {
        reject(new AuthenticationError('Invalid token header'));
        return;
      }

      // Get signing key and verify token
      this.getSigningKey(decodedHeader.header)
        .then((signingKey) => {
          jwt.verify(
            token,
            signingKey,
            {
              issuer: this.issuer,
              algorithms: ['RS256'],
            },
            (err, decoded) => {
              if (err) {
                reject(new AuthenticationError(`Token verification failed: ${err.message}`));
              } else {
                const payload = decoded as CognitoJwtPayload;

                // Validate token type (should be access token)
                if (payload.token_use !== 'access') {
                  reject(new AuthenticationError('Invalid token type. Access token required.'));
                  return;
                }

                resolve(payload);
              }
            }
          );
        })
        .catch((err) => {
          reject(new AuthenticationError(`Failed to get signing key: ${err.message}`));
        });
    });
  }

  /**
   * Extract user permissions from Cognito custom attributes
   */
  extractUserPermissions(payload: CognitoJwtPayload): UserPermissions {
    const roles: UserRole[] = [];
    const permissions: Permission[] = [];
    const features: string[] = [];

    // Parse custom attributes
    if (payload['custom:role']) {
      const roleString = payload['custom:role'];
      const parsedRoles = roleString.split(',').map((r) => r.trim() as UserRole);
      roles.push(...parsedRoles.filter((role) => Object.values(UserRole).includes(role)));
    }

    if (payload['custom:permissions']) {
      const permissionString = payload['custom:permissions'];
      const parsedPermissions = permissionString.split(',').map((p) => p.trim() as Permission);
      permissions.push(
        ...parsedPermissions.filter((perm) => Object.values(Permission).includes(perm))
      );
    }

    if (payload['custom:features']) {
      const featureString = payload['custom:features'];
      features.push(...featureString.split(',').map((f) => f.trim()));
    }

    // Default role if none specified
    if (roles.length === 0) {
      roles.push(UserRole.BASIC_USER);
    }

    // Default permissions based on roles
    this.addDefaultPermissions(roles, permissions);

    return { roles, permissions, features };
  }

  /**
   * Add default permissions based on user roles
   */
  private addDefaultPermissions(roles: UserRole[], permissions: Permission[]): void {
    for (const role of roles) {
      switch (role) {
        case UserRole.ADMIN:
          if (!permissions.includes(Permission.ADMIN_USERS))
            permissions.push(Permission.ADMIN_USERS);
          if (!permissions.includes(Permission.ADMIN_SYSTEM))
            permissions.push(Permission.ADMIN_SYSTEM);
          if (!permissions.includes(Permission.CHAT_UNLIMITED))
            permissions.push(Permission.CHAT_UNLIMITED);
          if (!permissions.includes(Permission.FEATURE_VOICE_CHAT))
            permissions.push(Permission.FEATURE_VOICE_CHAT);
          if (!permissions.includes(Permission.FEATURE_FILE_UPLOAD))
            permissions.push(Permission.FEATURE_FILE_UPLOAD);
          if (!permissions.includes(Permission.FEATURE_CUSTOM_MODELS)) {
            permissions.push(Permission.FEATURE_CUSTOM_MODELS);
          }
          break;
        case UserRole.PREMIUM_USER:
          if (!permissions.includes(Permission.CHAT_PREMIUM))
            permissions.push(Permission.CHAT_PREMIUM);
          if (!permissions.includes(Permission.FEATURE_VOICE_CHAT))
            permissions.push(Permission.FEATURE_VOICE_CHAT);
          if (!permissions.includes(Permission.FEATURE_FILE_UPLOAD))
            permissions.push(Permission.FEATURE_FILE_UPLOAD);
          break;
        case UserRole.BASIC_USER:
          if (!permissions.includes(Permission.CHAT_BASIC)) permissions.push(Permission.CHAT_BASIC);
          break;
        case UserRole.GUEST:
          // Guests have very limited permissions
          break;
      }
    }
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(userPermissions: UserPermissions, permission: Permission): boolean {
    return userPermissions.permissions.includes(permission);
  }

  /**
   * Check if user has specific role
   */
  hasRole(userPermissions: UserPermissions, role: UserRole): boolean {
    return userPermissions.roles.includes(role);
  }

  /**
   * Check if user has access to specific feature
   */
  hasFeature(userPermissions: UserPermissions, feature: string): boolean {
    return userPermissions.features.includes(feature);
  }
}
