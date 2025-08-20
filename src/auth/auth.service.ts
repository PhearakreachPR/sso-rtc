// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { compare, hash } from "bcryptjs";
import { Response } from "express";
import { Types } from "mongoose";
import { User } from "../users/schema/user.schema";
import { UsersService } from "../users/users.service";
import { TokenPayload } from "./token-payload.interface";

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  // ----------------- LOGIN -----------------
  async login(user: User, response: Response) {
    const expiresAccessToken = new Date(Date.now() + parseInt(this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")));
    const expiresRefreshToken = new Date(Date.now() + parseInt(this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")));

    const tokenPayload: TokenPayload = { userId: user._id.toString() };

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET"),
      expiresIn: `${this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")}ms`,
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow("JWT_REFRESH_TOKEN_SECRET"),
      expiresIn: `${this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")}ms`,
    });

    // Save hashed refresh token
    await this.usersService.updateUser(
      { _id: new Types.ObjectId(user._id) },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    // Set cookies
    const isProd = this.configService.get("NODE_ENV") === "production";
    response.cookie("Authentication", accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
      expires: expiresAccessToken,
    });
    response.cookie("Refresh", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
      path: "/auth/refresh",
      expires: expiresRefreshToken,
    });

    return { accessToken, refreshToken, user: await this.getSanitizedUser(user._id.toString()) };
  }

  // ----------------- TOKEN LOGIN -----------------
  async loginWithToken(token: string, type: "access" | "refresh", response: Response) {
    try {
      let payload: TokenPayload;
      if (type === "access") {
        payload = this.jwtService.verify(token, { secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") });
      } else {
        payload = this.jwtService.verify(token, { secret: this.configService.getOrThrow("JWT_REFRESH_TOKEN_SECRET") });
      }

      const user = await this.usersService.getUser({ _id: new Types.ObjectId(payload.userId) });
      if (!user) throw new UnauthorizedException("User not found");

      // Generate new tokens
      const { accessToken, refreshToken } = await this.generateTokens(user);
      await this.usersService.updateUser({ _id: user._id }, { $set: { refreshToken: await hash(refreshToken, 10) } });

      return { user: await this.getSanitizedUser(user._id.toString()), accessToken, refreshToken };
    } catch {
      throw new UnauthorizedException("Invalid or expired token");
    }
  }

  // ----------------- REFRESH -----------------
  async refresh(user: User, response: Response) {
    const dbUser = await this.usersService.getUser({ _id: new Types.ObjectId(user._id) });
    if (!dbUser?.refreshToken) throw new UnauthorizedException("Refresh token not found");

    return this.login(dbUser, response);
  }

  // ----------------- VERIFY USER -----------------
  async verifyUser(email: string, password: string) {
    const user = await this.usersService.getUser({ email });
    if (!user || !(await compare(password, user.password))) throw new UnauthorizedException("Invalid credentials");
    return user;
  }

  async verifyRefreshToken(refreshToken: string, userId: string) {
    const user = await this.usersService.getUser({ _id: new Types.ObjectId(userId) });
    if (!user?.refreshToken || !(await compare(refreshToken, user.refreshToken))) throw new UnauthorizedException("Invalid refresh token");
    return user;
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await compare(password, user.password))) {
      const { password, refreshToken, ...result } = user.toObject();
      return result;
    }
    return null;
  }

  private async getSanitizedUser(userId: string) {
    const user = await this.usersService["userModel"]
      .findById(new Types.ObjectId(userId))
      .populate({ path: "roles", populate: { path: "permissions" } })
      .lean()
      .exec();
    if (!user) throw new UnauthorizedException("User not found");
    const { password, refreshToken, ...sanitizedUser } = user as any;
    return sanitizedUser;
  }

  // ----------------- TOKEN / SSO SUPPORT -----------------
  async generateTokens(user: User) {
    const payload: TokenPayload = { userId: user._id.toString() };
    const accessToken = this.jwtService.sign(payload, { secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET"), expiresIn: `${this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")}ms` });
    const refreshToken = this.jwtService.sign(payload, { secret: this.configService.getOrThrow("JWT_REFRESH_TOKEN_SECRET"), expiresIn: `${this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")}ms` });
    return { accessToken, refreshToken };
  }

  getAccessTokenExpiration(): string {
    return this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS");
  }

  async getUserFromToken(token: string): Promise<any> {
    try {
      const payload = this.jwtService.verify(token, { secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") });
      const user = await this.usersService.getUser({ _id: payload.userId });
      if (!user) throw new UnauthorizedException("User not found");
      return { userId: user._id, email: user.email };
    } catch {
      throw new UnauthorizedException("Invalid token");
    }
  }

  async logDeviceAccess(userId: string, deviceInfo: { deviceInfo?: string; appName?: string; accessTime: Date; ipAddress?: string }) {
    console.log(`Device access logged for user ${userId}:`, deviceInfo);
  }

  async validateReturnUrl(returnUrl: string): Promise<string | null> {
    if (!returnUrl) return null;
    try {
      const url = new URL(returnUrl);
      const allowedWebsites = await this.getAllowedReturnWebsites();
      const isAllowed = allowedWebsites.some(a => url.hostname === a.domain || url.hostname.endsWith("." + a.domain));
      return isAllowed ? returnUrl : null;
    } catch {
      return null;
    }
  }

  private async getAllowedReturnWebsites(): Promise<Array<{ domain: string }>> {
    return [{ domain: "localhost" }, { domain: "localhost:3000" }, { domain: "127.0.0.1" }];
  }

  async getAllowedDomains(): Promise<string[]> {
    const sites = await this.getAllowedReturnWebsites();
    return sites.map(s => s.domain);
  }

  async verifyAccessToken(token: string): Promise<boolean> {
    try {
      const payload = this.jwtService.verify(token, { secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") });
      const user = await this.usersService.getUser({ _id: payload.userId });
      return !!user;
    } catch {
      return false;
    }
  }
}
