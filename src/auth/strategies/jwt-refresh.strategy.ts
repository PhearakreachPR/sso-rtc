// src/auth/strategies/jwt-refresh.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromBodyField('refreshToken'),
        ExtractJwt.fromExtractors([
          (request) => {
            return request?.cookies?.Refresh;
          },
        ]),
      ]),
      secretOrKey: configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: { userId: string }) {
    try {
      const refreshToken = req.body?.refreshToken || 
                          req.cookies?.Refresh || 
                          req.headers?.authorization?.replace('Bearer ', '');
      
      if (!refreshToken) {
        throw new Error('No refresh token provided');
      }

      const user = await this.authService.verifyRefreshToken(refreshToken, payload.userId);
      
      // Handle both Mongoose documents and plain objects
      const userObj = (user as any).toObject ? (user as any).toObject() : user;
      
      return { 
        ...userObj, 
        refreshToken,
        sub: payload.userId // Add sub for compatibility
      }; 
    } catch (error) {
      throw new Error('Refresh token validation failed: ' + error.message);
    }
  }
}