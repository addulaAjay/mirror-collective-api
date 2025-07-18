import jwt, { SignOptions } from 'jsonwebtoken';
import { JwtPayload, UserProfile } from '../../types/auth.types';
import { InvalidTokenError, TokenExpiredError } from '../../errors/auth.errors';

/**
 * JWT service for generating and verifying JSON Web Tokens
 */
export class JwtService {
  private accessTokenSecret: string;
  private refreshTokenSecret: string;
  private accessTokenExpiresIn: string;
  private refreshTokenExpiresIn: string;

  constructor() {
    this.accessTokenSecret = process.env.JWT_SECRET!;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET!;
    this.accessTokenExpiresIn = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m';
    this.refreshTokenExpiresIn = process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d';

    if (!this.accessTokenSecret || !this.refreshTokenSecret) {
      throw new Error(
        'Missing required JWT configuration. Please check your environment variables.'
      );
    }
  }

  /**
   * Generate access token for user
   */
  generateAccessToken(user: UserProfile): string {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      type: 'access',
    };

    const options: SignOptions = {
      expiresIn: this.accessTokenExpiresIn as any,
      issuer: 'mirror-collective-api',
      audience: 'mirror-collective-app',
      subject: user.id,
    };

    return jwt.sign(payload, this.accessTokenSecret, options);
  }

  /**
   * Generate refresh token for user
   */
  generateRefreshToken(user: UserProfile): string {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      type: 'refresh',
    };

    const options: SignOptions = {
      expiresIn: this.refreshTokenExpiresIn as any,
      issuer: 'mirror-collective-api',
      audience: 'mirror-collective-app',
      subject: user.id,
    };

    return jwt.sign(payload, this.refreshTokenSecret, options);
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(user: UserProfile): {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  } {
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken(user);

    // Calculate expires in seconds for access token
    const expiresIn = this.parseExpirationToSeconds(this.accessTokenExpiresIn);

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  }

  /**
   * Verify access token
   */
  verifyAccessToken(token: string): JwtPayload {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        issuer: 'mirror-collective-api',
        audience: 'mirror-collective-app',
      }) as JwtPayload;

      if (decoded.type !== 'access') {
        throw new InvalidTokenError('Invalid token type');
      }

      return decoded;
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new TokenExpiredError('Access token has expired');
      }

      if (error.name === 'JsonWebTokenError') {
        throw new InvalidTokenError('Invalid access token');
      }

      throw new InvalidTokenError(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Verify refresh token
   */
  verifyRefreshToken(token: string): JwtPayload {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        issuer: 'mirror-collective-api',
        audience: 'mirror-collective-app',
      }) as JwtPayload;

      if (decoded.type !== 'refresh') {
        throw new InvalidTokenError('Invalid token type');
      }

      return decoded;
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new TokenExpiredError('Refresh token has expired');
      }

      if (error.name === 'JsonWebTokenError') {
        throw new InvalidTokenError('Invalid refresh token');
      }

      throw new InvalidTokenError(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Decode token without verification (for debugging)
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      return jwt.decode(token) as JwtPayload;
    } catch {
      return null;
    }
  }

  /**
   * Get token expiration date
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = this.decodeToken(token);
      if (decoded?.exp) {
        return new Date(decoded.exp * 1000);
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    try {
      const expiration = this.getTokenExpiration(token);
      if (!expiration) return true;

      return expiration.getTime() < Date.now();
    } catch {
      return true;
    }
  }

  /**
   * Refresh access token using refresh token
   */
  refreshAccessToken(
    refreshToken: string,
    user: UserProfile
  ): { accessToken: string; expiresIn: number } {
    // Verify refresh token first
    this.verifyRefreshToken(refreshToken);

    // Generate new access token
    const accessToken = this.generateAccessToken(user);
    const expiresIn = this.parseExpirationToSeconds(this.accessTokenExpiresIn);

    return {
      accessToken,
      expiresIn,
    };
  }

  /**
   * Parse expiration string to seconds
   */
  private parseExpirationToSeconds(expiration: string): number {
    const timePattern = /^(\d+)([smhd])$/;
    const match = expiration.match(timePattern);

    if (!match) {
      throw new Error(`Invalid expiration format: ${expiration}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      default:
        throw new Error(`Invalid time unit: ${unit}`);
    }
  }

  /**
   * Generate a random JWT secret (for development/testing)
   */
  static generateSecret(length: number = 64): string {
    const crypto = require('crypto');
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Validate JWT configuration
   */
  validateConfiguration(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.accessTokenSecret) {
      errors.push('JWT_SECRET is required');
    } else if (this.accessTokenSecret.length < 32) {
      errors.push('JWT_SECRET should be at least 32 characters long');
    }

    if (!this.refreshTokenSecret) {
      errors.push('JWT_REFRESH_SECRET is required');
    } else if (this.refreshTokenSecret.length < 32) {
      errors.push('JWT_REFRESH_SECRET should be at least 32 characters long');
    }

    if (this.accessTokenSecret === this.refreshTokenSecret) {
      errors.push('JWT_SECRET and JWT_REFRESH_SECRET should be different');
    }

    try {
      this.parseExpirationToSeconds(this.accessTokenExpiresIn);
    } catch {
      errors.push(`Invalid JWT_ACCESS_TOKEN_EXPIRES_IN format: ${this.accessTokenExpiresIn}`);
    }

    try {
      this.parseExpirationToSeconds(this.refreshTokenExpiresIn);
    } catch {
      errors.push(`Invalid JWT_REFRESH_TOKEN_EXPIRES_IN format: ${this.refreshTokenExpiresIn}`);
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
