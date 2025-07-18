import { UserProfile, JwtPayload } from '../../types/auth.types';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface RefreshTokenResult {
  accessToken: string;
  expiresIn: number;
}

export interface ITokenService {
  generateTokenPair(user: UserProfile): TokenPair;
  verifyAccessToken(token: string): JwtPayload;
  verifyRefreshToken(token: string): JwtPayload;
  refreshAccessToken(refreshToken: string, user: UserProfile): RefreshTokenResult;
  isTokenExpired(token: string): boolean;
  getTokenExpiration(token: string): Date | null;
  validateConfiguration(): { isValid: boolean; errors: string[] };
}