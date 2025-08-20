import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Res,
  Req,
  UseGuards,
  Render,
} from "@nestjs/common";
import type { Response } from "express";
import { AuthService } from "./auth.service";
import { JwtService } from "@nestjs/jwt";
import type { SessionService } from "./services/session.service";
import { LocalAuthGuard } from "./guards/local-auth.guard";
import { JwtAuthGuard } from "./guards/jwt-auth.guard";
import { JwtRefreshAuthGuard } from "./guards/jwt-refresh-auth.guard";
import { CurrentUser } from "./current-user.decorator";
import type { User } from "../users/schema/user.schema";

class TokenLoginDto {
  token: string;
  type: "access" | "refresh";
}

@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
  ) {}

  // --- Login page ---
  @Get("login")
  @Render("login")
  showLoginPage(@Query("returnUrl") returnUrl?: string, @Query("error") error?: string) {
    return { returnUrl, error };
  }

  // --- Login with LocalAuthGuard ---
  @Post("login")
  @UseGuards(LocalAuthGuard)
  async login(
    @CurrentUser() user: User,
    @Body("returnUrl") returnUrl: string,
    @Res() res: Response,
  ) {
    try {
      const result = await this.authService.login(user, res);

      if (returnUrl) {
        const redirectUrl = new URL(returnUrl);
        redirectUrl.searchParams.set("access_token", result.accessToken);
        redirectUrl.searchParams.set("user_id", result.user._id.toString());
        res.redirect(redirectUrl.toString());
        return;
      }

      res.json(result);
    } catch (error) {
      const loginUrl = `/auth/login?error=${encodeURIComponent("Login failed")}`;
      if (returnUrl) {
        res.redirect(`${loginUrl}&returnUrl=${encodeURIComponent(returnUrl)}`);
        return;
      }
      res.redirect(loginUrl);
    }
  }

  // --- Refresh token ---
  @Post("refresh")
  @UseGuards(JwtRefreshAuthGuard)
  async refreshToken(@CurrentUser() user: User, @Res() res: Response) {
    const result = await this.authService.refresh(user, res);
    return res.json(result);
  }

  // --- Token-login ---
  @Post("token-login")
  async loginWithToken(@Body() body: TokenLoginDto, @Res() res: Response) {
    const { token, type } = body;
    const result = await this.authService.loginWithToken(token, type, res);
    return res.json(result);
  }

  // --- Verify token ---
  @Get("verify-token")
  @UseGuards(JwtAuthGuard)
  verifyToken(@CurrentUser() user: any) {
    return {
      valid: true,
      user: {
        id: user.sub,
        email: user.email,
        roles: user.roles,
      },
      message: "Token is valid",
    };
  }

  // --- Token status ---
  @Get("token-status")
  checkTokenStatus(@Req() req: any) {
    const token = this.extractTokenFromHeader(req);

    if (!token) {
      return { isLoggedIn: false, message: "No token provided" };
    }

    try {
      const payload = this.jwtService.verify(token);
      return {
        isLoggedIn: true,
        user: {
          id: payload.sub,
          email: payload.email,
          roles: payload.roles,
        },
        expiresAt: new Date(payload.exp * 1000),
      };
    } catch (error) {
      return {
        isLoggedIn: false,
        message: "Invalid or expired token",
        error: error.message,
      };
    }
  }

  // --- Sessions ---
  @Get("sessions")
  @UseGuards(JwtAuthGuard)
  async getUserSessions(@CurrentUser() user: any) {
    const sessions = await this.sessionService.getUserSessions(user.sub);
    return {
      sessions: sessions.map((session) => ({
        deviceId: session.deviceId,
        deviceInfo: session.deviceInfo,
        lastActivity: session.lastActivity,
        createdAt: session.createdAt,
        isCurrentSession: session.accessToken === user.accessToken,
      })),
    };
  }

  // --- Logout ---
  @Post("logout")
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: any) {
    const token = this.extractTokenFromHeader(req);
    if (token) {
      await this.sessionService.invalidateSession(token);
    }
    return { message: "Logged out successfully" };
  }

  // --- Logout all ---
  @Post("logout-all")
  @UseGuards(JwtAuthGuard)
  async logoutAll(@CurrentUser() user: any) {
    await this.sessionService.invalidateAllUserSessions(user.sub);
    return { message: "Logged out from all devices" };
  }

  // --- Device status ---
  @Get("device-status")
  async checkDeviceStatus(@Req() req: any) {
    const deviceInfo = req.deviceInfo;
    const deviceId = this.sessionService.generateDeviceId(deviceInfo);
    const hasActiveSession = await this.sessionService.hasActiveSession(deviceId);

    return {
      deviceId,
      hasActiveSession,
      deviceInfo,
    };
  }

  // --- Helper ---
  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }
}
