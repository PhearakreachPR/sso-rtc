// src/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Request } from "express";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../../users/users.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // 1) Check "token" cookie (PHP-style)
        (request: Request) => request?.cookies?.token,
        // 2) Check "Authentication" cookie (NestJS style)
        (request: Request) => request?.cookies?.Authentication,
        // 3) Check Bearer token
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET"),
    });
  }

  async validate(payload: any) {
    // payload is what you signed in AuthService.login()
    const user = await this.usersService.getUser({ _id: payload.userId });
    if (!user) {
      throw new UnauthorizedException("User not found or token invalid");
    }

    return {
      _id: user._id.toString(),
      email: user.email,
      roles: user.roles?.map(r => r.toString?.() ?? r) || [],
    };
  }
}
