// src/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Request } from "express";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../../users/users.service";
import { TokenPayload } from "../token-payload.interface";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // 1) Extract from cookie
        (request: Request) => request?.cookies?.Authentication,
        // 2) Extract from Bearer token
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET"),
    });
  }

  async validate(payload: TokenPayload) {
    const user = await this.usersService.getUser({ _id: payload.userId });
    if (!user) {
      throw new UnauthorizedException("User not found or token invalid");
    }

    return {
      _id: user._id,
      email: user.email,
      roles: user.roles,
    };
  }
}
