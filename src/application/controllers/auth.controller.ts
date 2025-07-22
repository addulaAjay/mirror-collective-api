import { NextFunction, Request, Response } from 'express';
import { UserProfile } from '../../types/auth.types';

// Extend Express Request interface to include user
interface AuthenticatedRequest extends Request {
  user?: UserProfile;
}

import {
  ConfirmEmailUseCase,
  ConfirmPasswordResetUseCase,
  InitiatePasswordResetUseCase,
  LoginUserUseCase,
  RefreshTokenUseCase,
  RegisterUserUseCase,
  ResendVerificationCodeUseCase,
} from '../../domain/use-cases';
import { IAuthRepository } from '../../domain/repositories';

export class AuthController {
  constructor(
    private registerUserUseCase: RegisterUserUseCase,
    private loginUserUseCase: LoginUserUseCase,
    private initiatePasswordResetUseCase: InitiatePasswordResetUseCase,
    private confirmPasswordResetUseCase: ConfirmPasswordResetUseCase,
    private refreshTokenUseCase: RefreshTokenUseCase,
    private confirmEmailUseCase: ConfirmEmailUseCase,
    private resendVerificationCodeUseCase: ResendVerificationCodeUseCase,
    private authRepository: IAuthRepository
  ) {}

  register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.registerUserUseCase.execute(req.body);
      res.status(201).json(result);
    } catch (error) {
      next(error);
    }
  };

  login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.loginUserUseCase.execute(req.body);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };

  forgotPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.initiatePasswordResetUseCase.execute(req.body);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };

  resetPassword = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.confirmPasswordResetUseCase.execute(req.body);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };

  refreshToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          error: 'Validation Error',
          message: 'Refresh token is required',
        });
        return;
      }

      const result = await this.refreshTokenUseCase.execute({ refreshToken });
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };



  getCurrentUser = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication Required',
          message: 'User not authenticated',
        });
        return;
      }

      res.status(200).json({
        success: true,
        user: req.user,
      });
    } catch (error) {
      next(error);
    }
  };

  logout = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication Required',
          message: 'User not authenticated',
        });
        return;
      }

      // In a production system, you might want to:
      // 1. Add the tokens to a blacklist
      // 2. Store logout events in a database
      // 3. Notify other services about the logout

      res.status(200).json({
        success: true,
        message: 'Logged out successfully',
      });
    } catch (error) {
      next(error);
    }
  };

  deleteAccount = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication Required',
          message: 'User not authenticated',
        });
        return;
      }

      await this.authRepository.deleteUser(req.user.email);

      res.status(200).json({
        success: true,
        message: 'Account deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  };

  confirmEmail = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const result = await this.confirmEmailUseCase.execute(req.body);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };

  resendVerificationCode = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const result = await this.resendVerificationCodeUseCase.execute(req.body);
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  };
}
