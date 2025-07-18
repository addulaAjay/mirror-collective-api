import { ITokenService, TokenPair, RefreshTokenResult } from '../../domain/repositories/token.repository';
import { UserProfile, JwtPayload } from '../../types/auth.types';
import { JwtService } from '../../services';

export class JwtTokenService implements ITokenService {
  private jwtService: JwtService;

  constructor() {
    this.jwtService = new JwtService();
  }

  generateTokenPair(user: UserProfile): TokenPair {
    return this.jwtService.generateTokenPair(user);
  }

  verifyAccessToken(token: string): JwtPayload {
    return this.jwtService.verifyAccessToken(token);
  }

  verifyRefreshToken(token: string): JwtPayload {
    return this.jwtService.verifyRefreshToken(token);
  }

  refreshAccessToken(refreshToken: string, user: UserProfile): RefreshTokenResult {
    return this.jwtService.refreshAccessToken(refreshToken, user);
  }

  isTokenExpired(token: string): boolean {
    return this.jwtService.isTokenExpired(token);
  }

  getTokenExpiration(token: string): Date | null {
    return this.jwtService.getTokenExpiration(token);
  }

  validateConfiguration(): { isValid: boolean; errors: string[] } {
    return this.jwtService.validateConfiguration();
  }
}