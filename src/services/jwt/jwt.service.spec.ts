import { beforeEach, describe, expect, it, vi } from 'vitest';
import jwt from 'jsonwebtoken';
import { JwtService } from './jwt.service';
import { UserProfile } from '../../types/auth.types';
import { InvalidTokenError, TokenExpiredError } from '../../errors/auth.errors';

describe('JwtService', () => {
  let jwtService: JwtService;
  const mockUser: UserProfile = {
    id: 'test-user-id',
    email: 'test@example.com',
    firstName: 'John',
    lastName: 'Doe',
    provider: 'cognito',
    emailVerified: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    roles: [],
    permissions: [],
    features: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Set required environment variables
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-purposes-only-must-be-long';
    process.env.JWT_REFRESH_SECRET =
      'test-jwt-refresh-secret-key-for-testing-purposes-only-must-be-long';
    process.env.JWT_ACCESS_TOKEN_EXPIRES_IN = '15m';
    process.env.JWT_REFRESH_TOKEN_EXPIRES_IN = '7d';

    jwtService = new JwtService();
  });

  describe('constructor', () => {
    it('should initialize with environment variables', () => {
      expect(jwtService).toBeInstanceOf(JwtService);
    });

    it('should throw error when JWT_SECRET is missing', () => {
      delete process.env.JWT_SECRET;

      expect(() => new JwtService()).toThrow(
        'Missing required JWT configuration. Please check your environment variables.'
      );
    });

    it('should throw error when JWT_REFRESH_SECRET is missing', () => {
      delete process.env.JWT_REFRESH_SECRET;

      expect(() => new JwtService()).toThrow(
        'Missing required JWT configuration. Please check your environment variables.'
      );
    });

    it('should use default expiration times when not provided', () => {
      delete process.env.JWT_ACCESS_TOKEN_EXPIRES_IN;
      delete process.env.JWT_REFRESH_TOKEN_EXPIRES_IN;

      const service = new JwtService();
      expect(service).toBeInstanceOf(JwtService);
    });
  });

  describe('generateAccessToken', () => {
    it('should generate a valid access token', () => {
      const token = jwtService.generateAccessToken(mockUser);

      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT format

      const decoded = jwt.decode(token) as any;
      expect(decoded.userId).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
      expect(decoded.type).toBe('access');
      expect(decoded.iss).toBe('mirror-collective-api');
      expect(decoded.aud).toBe('mirror-collective-app');
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate a valid refresh token', () => {
      const token = jwtService.generateRefreshToken(mockUser);

      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT format

      const decoded = jwt.decode(token) as any;
      expect(decoded.userId).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
      expect(decoded.type).toBe('refresh');
      expect(decoded.iss).toBe('mirror-collective-api');
      expect(decoded.aud).toBe('mirror-collective-app');
    });
  });

  describe('generateTokenPair', () => {
    it('should generate both access and refresh tokens', () => {
      const tokens = jwtService.generateTokenPair(mockUser);

      expect(tokens).toHaveProperty('accessToken');
      expect(tokens).toHaveProperty('refreshToken');
      expect(tokens).toHaveProperty('expiresIn');

      expect(typeof tokens.accessToken).toBe('string');
      expect(typeof tokens.refreshToken).toBe('string');
      expect(typeof tokens.expiresIn).toBe('number');
      expect(tokens.expiresIn).toBe(900); // 15 minutes
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify a valid access token', () => {
      const token = jwtService.generateAccessToken(mockUser);
      const decoded = jwtService.verifyAccessToken(token);

      expect(decoded.userId).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
      expect(decoded.type).toBe('access');
    });

    it('should throw error for invalid token type', () => {
      const refreshToken = jwtService.generateRefreshToken(mockUser);

      expect(() => jwtService.verifyAccessToken(refreshToken)).toThrow(InvalidTokenError);
    });

    it('should throw error for expired token', () => {
      const expiredToken = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'access' },
        process.env.JWT_SECRET!,
        { expiresIn: '-1s' }
      );

      expect(() => jwtService.verifyAccessToken(expiredToken)).toThrow(TokenExpiredError);
    });

    it('should throw error for invalid token', () => {
      expect(() => jwtService.verifyAccessToken('invalid-token')).toThrow(InvalidTokenError);
    });

    it('should throw error for token with wrong secret', () => {
      const wrongToken = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'access' },
        'wrong-secret'
      );

      expect(() => jwtService.verifyAccessToken(wrongToken)).toThrow(InvalidTokenError);
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify a valid refresh token', () => {
      const token = jwtService.generateRefreshToken(mockUser);
      const decoded = jwtService.verifyRefreshToken(token);

      expect(decoded.userId).toBe(mockUser.id);
      expect(decoded.email).toBe(mockUser.email);
      expect(decoded.type).toBe('refresh');
    });

    it('should throw error for invalid token type', () => {
      const accessToken = jwtService.generateAccessToken(mockUser);

      expect(() => jwtService.verifyRefreshToken(accessToken)).toThrow(InvalidTokenError);
    });

    it('should throw error for expired token', () => {
      const expiredToken = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '-1s' }
      );

      expect(() => jwtService.verifyRefreshToken(expiredToken)).toThrow(TokenExpiredError);
    });

    it('should throw error for invalid token', () => {
      expect(() => jwtService.verifyRefreshToken('invalid-token')).toThrow(InvalidTokenError);
    });
  });

  describe('decodeToken', () => {
    it('should decode a valid token without verification', () => {
      const token = jwtService.generateAccessToken(mockUser);
      const decoded = jwtService.decodeToken(token);

      expect(decoded).toBeTruthy();
      expect(decoded?.userId).toBe(mockUser.id);
      expect(decoded?.email).toBe(mockUser.email);
    });

    it('should return null for invalid token', () => {
      const decoded = jwtService.decodeToken('invalid-token');
      expect(decoded).toBeNull();
    });
  });

  describe('getTokenExpiration', () => {
    it('should get expiration date from valid token', () => {
      const token = jwtService.generateAccessToken(mockUser);
      const expiration = jwtService.getTokenExpiration(token);

      expect(expiration).toBeInstanceOf(Date);
      expect(expiration!.getTime()).toBeGreaterThan(Date.now());
    });

    it('should return null for token without expiration', () => {
      const tokenWithoutExp = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'access' },
        process.env.JWT_SECRET!
      );

      const expiration = jwtService.getTokenExpiration(tokenWithoutExp);
      expect(expiration).toBeNull();
    });

    it('should return null for invalid token', () => {
      const expiration = jwtService.getTokenExpiration('invalid-token');
      expect(expiration).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for valid token', () => {
      const token = jwtService.generateAccessToken(mockUser);
      const expired = jwtService.isTokenExpired(token);

      expect(expired).toBe(false);
    });

    it('should return true for expired token', () => {
      const expiredToken = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'access' },
        process.env.JWT_SECRET!,
        { expiresIn: '-1s' }
      );

      const expired = jwtService.isTokenExpired(expiredToken);
      expect(expired).toBe(true);
    });

    it('should return true for invalid token', () => {
      const expired = jwtService.isTokenExpired('invalid-token');
      expect(expired).toBe(true);
    });

    it('should return true for token without expiration', () => {
      const tokenWithoutExp = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'access' },
        process.env.JWT_SECRET!
      );

      const expired = jwtService.isTokenExpired(tokenWithoutExp);
      expect(expired).toBe(true);
    });
  });

  describe('refreshAccessToken', () => {
    it('should generate new access token from valid refresh token', () => {
      const refreshToken = jwtService.generateRefreshToken(mockUser);
      const result = jwtService.refreshAccessToken(refreshToken, mockUser);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('expiresIn');
      expect(typeof result.accessToken).toBe('string');
      expect(result.expiresIn).toBe(900); // 15 minutes

      // Verify the new access token is valid
      const decoded = jwtService.verifyAccessToken(result.accessToken);
      expect(decoded.userId).toBe(mockUser.id);
    });

    it('should throw error for invalid refresh token', () => {
      expect(() => jwtService.refreshAccessToken('invalid-token', mockUser)).toThrow(
        InvalidTokenError
      );
    });

    it('should throw error for expired refresh token', () => {
      const expiredToken = jwt.sign(
        { userId: mockUser.id, email: mockUser.email, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '-1s' }
      );

      expect(() => jwtService.refreshAccessToken(expiredToken, mockUser)).toThrow(
        TokenExpiredError
      );
    });
  });

  describe('parseExpirationToSeconds', () => {
    it('should parse seconds correctly', () => {
      const service = jwtService as any;
      expect(service.parseExpirationToSeconds('30s')).toBe(30);
    });

    it('should parse minutes correctly', () => {
      const service = jwtService as any;
      expect(service.parseExpirationToSeconds('15m')).toBe(900);
    });

    it('should parse hours correctly', () => {
      const service = jwtService as any;
      expect(service.parseExpirationToSeconds('2h')).toBe(7200);
    });

    it('should parse days correctly', () => {
      const service = jwtService as any;
      expect(service.parseExpirationToSeconds('7d')).toBe(604800);
    });

    it('should throw error for invalid format', () => {
      const service = jwtService as any;
      expect(() => service.parseExpirationToSeconds('invalid')).toThrow(
        'Invalid expiration format'
      );
    });

    it('should throw error for invalid unit', () => {
      const service = jwtService as any;
      expect(() => service.parseExpirationToSeconds('10x')).toThrow('Invalid expiration format');
    });
  });

  describe('generateSecret', () => {
    it('should generate a random secret with default length', () => {
      const secret = JwtService.generateSecret();
      expect(typeof secret).toBe('string');
      expect(secret.length).toBe(128); // 64 bytes * 2 (hex)
    });

    it('should generate a random secret with custom length', () => {
      const secret = JwtService.generateSecret(32);
      expect(typeof secret).toBe('string');
      expect(secret.length).toBe(64); // 32 bytes * 2 (hex)
    });
  });

  describe('validateConfiguration', () => {
    it('should return valid for correct configuration', () => {
      const validation = jwtService.validateConfiguration();
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect missing JWT_SECRET', () => {
      const originalSecret = process.env.JWT_SECRET;
      process.env.JWT_SECRET = 'test-short';
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('JWT_SECRET should be at least 32 characters long');

      process.env.JWT_SECRET = originalSecret;
    });

    it('should detect short JWT_SECRET', () => {
      process.env.JWT_SECRET = 'short';
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('JWT_SECRET should be at least 32 characters long');
    });

    it('should detect missing JWT_REFRESH_SECRET', () => {
      const originalRefreshSecret = process.env.JWT_REFRESH_SECRET;
      process.env.JWT_REFRESH_SECRET = 'short';
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain(
        'JWT_REFRESH_SECRET should be at least 32 characters long'
      );

      process.env.JWT_REFRESH_SECRET = originalRefreshSecret;
    });

    it('should detect identical secrets', () => {
      const sameSecret = 'same-secret-for-both-access-and-refresh-tokens';
      process.env.JWT_SECRET = sameSecret;
      process.env.JWT_REFRESH_SECRET = sameSecret;
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('JWT_SECRET and JWT_REFRESH_SECRET should be different');
    });

    it('should detect invalid expiration format', () => {
      process.env.JWT_ACCESS_TOKEN_EXPIRES_IN = 'invalid';
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(
        validation.errors.some((err) => err.includes('Invalid JWT_ACCESS_TOKEN_EXPIRES_IN format'))
      ).toBe(true);
    });

    it('should detect invalid refresh expiration format', () => {
      process.env.JWT_REFRESH_TOKEN_EXPIRES_IN = 'invalid';
      const service = new JwtService();
      const validation = service.validateConfiguration();

      expect(validation.isValid).toBe(false);
      expect(
        validation.errors.some((err) => err.includes('Invalid JWT_REFRESH_TOKEN_EXPIRES_IN format'))
      ).toBe(true);
    });
  });
});
