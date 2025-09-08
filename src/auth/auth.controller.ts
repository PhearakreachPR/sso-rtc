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
  UnauthorizedException,
  BadRequestException,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { JwtService } from "@nestjs/jwt";
import { SessionService } from "./services/session.service";
import { LocalAuthGuard } from "./guards/local-auth.guard";
import { JwtAuthGuard } from "./guards/jwt-auth.guard";
import { JwtRefreshAuthGuard } from "./guards/jwt-refresh-auth.guard";
import { CurrentUser } from "./current-user.decorator";
import type { User } from "../users/schema/user.schema";
import { DeviceInfo } from "src/interfaces/device-info.interface";
import { createUserRequest } from "src/users/dto/create-user.request";
import { SSOService } from "./services/sso.service";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "src/users/users.service";
import type { Response, Request } from "express";

class TokenLoginDto {
  token: string;
  type: "access" | "refresh";
}

export class LoginDto {
  email: string;
  password: string;
  returnUrl?: string;
}

interface RequestWithCookies extends Request {
  cookies: Record<string, string>;
}

@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
    private readonly ssoService: SSOService,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {}

  @Get("test")
  test() {
    return {
      message: "Auth controller working",
      timestamp: new Date(),
      sso_enabled: true,
    };
  }

  // --- Register user ---
  @Post("register")
  async register(
    @Body() registerDto: createUserRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const user = await this.authService.register(registerDto);
      const result = await this.authService.login(user, res);
      await this.createEncryptedSSOSession(user, res);

      return {
        success: true,
        message: "User registered successfully",
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      };
    } catch (error) {
      throw new BadRequestException(`Registration failed: ${error.message}`);
    }
  }

  // --- Enhanced SSO Check with encrypted cookies ---
  @Get("sso-check")
  async ssoCheck(
    @Req() req: RequestWithCookies,
    @Res({ passthrough: true }) res: Response,
    @Query("returnUrl") returnUrl?: string,
    @Query("targetDomain") targetDomain?: string,
  ) {
    try {
      const encryptedToken = req.cookies?.sso_token;

      if (encryptedToken) {
        try {
          const token = this.decryptToken(encryptedToken);
          const isValid = await this.authService.verifyAccessToken(token);

          if (isValid) {
            const userInfo = await this.getUserFromToken(token); // userId is string now

            if (returnUrl) {
              const redirectUrl = new URL(returnUrl);
              redirectUrl.searchParams.set("access_token", token);
              redirectUrl.searchParams.set("user_id", userInfo.userId); // string
              return {
                success: true,
                authenticated: true,
                user: userInfo,
                redirectUrl: redirectUrl.toString(),
                message: "Auto-logged in via encrypted SSO cookie",
              };
            }

            return {
              success: true,
              authenticated: true,
              user: userInfo,
              accessToken: token,
              message: "Valid SSO session found",
            };
          }
        } catch (decryptError: any) {
          console.warn("Failed to decrypt SSO token:", decryptError.message);
          res.clearCookie("sso_token");
        }
      }

      const ssoResult = await this.ssoService.autoLoginFromSSO(req, res, returnUrl);

      if (ssoResult.success) {
        return {
          success: true,
          authenticated: true,
          user: ssoResult.user,
          accessToken: ssoResult.tokens?.accessToken,
          redirectUrl: ssoResult.redirectUrl,
          message: "Auto-logged in via SSO service",
        };
      }

      return {
        success: false,
        authenticated: false,
        loginUrl: `/auth/login${returnUrl ? `?returnUrl=${encodeURIComponent(returnUrl)}` : ""}`,
        message: "No valid SSO session found",
      };
    } catch (error) {
      console.error("SSO check failed:", error);
      return {
        success: false,
        authenticated: false,
        loginUrl: `/auth/login${returnUrl ? `?returnUrl=${encodeURIComponent(returnUrl)}` : ""}`,
        message: "SSO check failed",
      };
    }
  }

  // --- Login page ---
  @Get("login")
  @Render("login")
  showLoginPage(@Query("returnUrl") returnUrl?: string, @Query("error") error?: string) {
    return { returnUrl, error };
  }

  // --- Enhanced Login with encrypted SSO cookie ---
  @Post("login")
  @UseGuards(LocalAuthGuard)
  async login(
    @CurrentUser() user: User,
    @Body("returnUrl") returnUrl: string,
    @Res({ passthrough: true }) res: Response,
    @Req() req: any,
  ) {
    try {
      const result = await this.authService.login(user, res);
      const originDomain = req.get("host") || "localhost";
      await this.ssoService.createSSOSession(user, res, originDomain);
      await this.createEncryptedSSOSession(user, res);

      if (returnUrl) {
        const validatedUrl = await this.authService.validateReturnUrl(returnUrl);
        if (validatedUrl) {
          const redirectUrl = new URL(validatedUrl);
          redirectUrl.searchParams.set("access_token", result.accessToken);
          redirectUrl.searchParams.set("user_id", result.user._id.toString());
          if (req.deviceInfo) {
            redirectUrl.searchParams.set("device_info", JSON.stringify(req.deviceInfo));
          }
          return {
            success: true,
            message: "Login successful",
            redirectUrl: redirectUrl.toString(),
            ...result,
          };
        }
      }

      return {
        success: true,
        message: "Login successful",
        ...result,
      };
    } catch (error: any) {
      throw new UnauthorizedException(`Login failed: ${error.message}`);
    }
  }

  // --- API Login endpoint ---
  @Post("api-login")
  async apiLogin(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: Response) {
    try {
      if (!loginDto.email || !loginDto.password) {
        throw new BadRequestException("Email and password are required");
      }

      const user = await this.authService.validateUser(loginDto.email, loginDto.password);
      if (!user) throw new UnauthorizedException("Invalid email or password");

      const result = await this.authService.login(user, res);
      await this.createEncryptedSSOSession(user, res);

      if (loginDto.returnUrl) {
        const validatedUrl = await this.authService.validateReturnUrl(loginDto.returnUrl);
        if (validatedUrl) {
          const redirectUrl = new URL(validatedUrl);
          redirectUrl.searchParams.set("access_token", result.accessToken);
          redirectUrl.searchParams.set("user_id", result.user._id.toString());
          return {
            success: true,
            message: "Login successful",
            redirectUrl: redirectUrl.toString(),
            ...result,
          };
        }
      }

      return {
        success: true,
        message: "Login successful",
        ...result,
      };
    } catch (error: any) {
      if (error instanceof UnauthorizedException || error instanceof BadRequestException) {
        throw error;
      }
      throw new UnauthorizedException(`Login failed: ${error.message}`);
    }
  }

  // --- Enhanced SSO Status Check ---
  @Get("sso-status")
  async checkSSOStatus(@Req() req: RequestWithCookies) {
    try {
      const encryptedToken = req.cookies?.sso_token;

      if (encryptedToken) {
        try {
          const token = this.decryptToken(encryptedToken);
          const payload = this.jwtService.verify(token, {
            secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
          });

          const user = await this.usersService.getUser({ _id: payload.userId });

          if (user) {
            return {
              isLoggedIn: true,
              user: {
                id: user._id.toString(), // <-- string
                email: user.email,
              },
              expiresAt: new Date(payload.exp * 1000),
              source: "encrypted_cookie",
            };
          }
        } catch (error: any) {
          console.warn("Invalid encrypted SSO token:", error.message);
        }
      }

      const ssoPayload = await this.ssoService.checkSSOSession(req);

      if (ssoPayload) {
        return {
          isLoggedIn: true,
          user: {
            id: String(ssoPayload.userId),
            email: ssoPayload.email,
            firstName: ssoPayload.firstName,
            lastName: ssoPayload.lastName,
            roles: ssoPayload.roles,
          },
          expiresAt: new Date(ssoPayload.exp),
          source: "sso_service",
        };
      }

      return { isLoggedIn: false };
    } catch (error: any) {
      return {
        isLoggedIn: false,
        error: error.message,
      };
    }
  }

  // --- Simple Token Verification ---
  @Get("check-token")
  async checkToken(
    @Query("token") token: string,
    @Query("device_info") deviceInfo?: string,
    @Query("app_name") appName?: string,
  ) {
    if (!token) {
      return { valid: false, message: "No token provided" };
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      });

      const user = await this.usersService.getUser({ _id: payload.userId });
      if (!user) return { valid: false, message: "User not found" };

      if (deviceInfo || appName) {
        await this.authService.logDeviceAccess(user._id.toString(), {
          deviceInfo,
          appName,
          accessTime: new Date(),
        });
      }

      return {
        valid: true,
        user: {
          id: user._id.toString(), // <-- string
          email: user.email,
        },
        message: "Token is valid",
        device_info: deviceInfo,
        app_name: appName,
      };
    } catch {
      return { valid: false, message: "Invalid or expired token" };
    }
  }

  @Post("sso-login")
  async ssoAutoLogin(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body("returnUrl") returnUrl?: string,
  ) {
    try {
      const result = await this.ssoService.autoLoginFromSSO(req, res, returnUrl);

      if (result.success) {
        if (returnUrl && result.redirectUrl) {
          return { success: true, redirectUrl: result.redirectUrl };
        } else {
          return {
            success: true,
            user: result.user,
            accessToken: result.tokens?.accessToken,
            refreshToken: result.tokens?.refreshToken,
          };
        }
      } else {
        throw new UnauthorizedException("No valid SSO session found");
      }
    } catch (error: any) {
      throw new UnauthorizedException(`SSO auto-login failed: ${error.message}`);
    }
  }

  @Post("refresh")
  @UseGuards(JwtRefreshAuthGuard)
  async refreshToken(@CurrentUser() user: User, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.refresh(user, res);
    return result;
  }

  @Post("token-login")
  async loginWithToken(@Body() body: TokenLoginDto, @Res({ passthrough: true }) res: Response) {
    const { token, type } = body;
    const result = await this.authService.loginWithToken(token, type, res);
    return result;
  }

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

  @Get("token-status")
  checkTokenStatus(@Req() req: any) {
    const token = this.extractTokenFromHeader(req);
    if (!token) return { isLoggedIn: false, message: "No token provided" };

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      });
      return {
        isLoggedIn: true,
        user: {
          id: payload.sub || payload.userId,
          email: payload.email,
          roles: payload.roles,
        },
        expiresAt: new Date(payload.exp * 1000),
      };
    } catch (error: any) {
      return {
        isLoggedIn: false,
        message: "Invalid or expired token",
        error: error.message,
      };
    }
  }

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
@Get("logout")
async getLogout(
  @Req() req: Request,
  @Res() res: Response,
  @Query("redirect") redirect?: string,
) {
  try {
    // Invalidate session token if provided
    const token = this.extractTokenFromHeader(req);
    if (token) {
      await this.sessionService.invalidateSession(token);
    }

    // Clear SSO + cookies
    await this.ssoService.clearSSOSession(res);
    this.clearEncryptedSSOCookie(res);
    res.clearCookie("Authentication");
    res.clearCookie("Refresh");

    // Redirect if provided
    if (redirect) {
      return res.redirect(redirect);
    }

    return res.json({ success: true, message: "Logged out successfully" });
  } catch (error: any) {
    console.error("Logout failed:", error.message);
    return res.json({ success: false, message: "Logout failed", error: error.message });
  }
}
  @Post("logout")
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    try {
      const token = this.extractTokenFromHeader(req);
      if (token) await this.sessionService.invalidateSession(token);

      await this.ssoService.clearSSOSession(res);
      this.clearEncryptedSSOCookie(res);

      res.clearCookie("Authentication");
      res.clearCookie("Refresh");

      return { success: true, message: "Logged out successfully from all sites" };
    } catch {
      return { success: true, message: "Logged out successfully" };
    }
  }

  @Post("sso-refresh")
  async refreshSSO(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    try {
      const success = await this.ssoService.refreshSSOSession(req, res);
      if (success) return { success: true, message: "SSO session refreshed" };
      throw new UnauthorizedException("No valid SSO session");
    } catch (error: any) {
      throw new UnauthorizedException(`SSO refresh failed: ${error.message}`);
    }
  }

  @Get("sso-login-url")
  getSSOLoginUrl(@Query("targetDomain") targetDomain: string, @Query("returnUrl") returnUrl?: string) {
    const loginUrl = this.ssoService.generateSSOLoginUrl(targetDomain, returnUrl);
    return { loginUrl };
  }

  @Get("device-status")
  async checkDeviceStatus(@Req() req: { deviceInfo: DeviceInfo }) {
    const deviceInfo = req.deviceInfo;
    const deviceId = this.sessionService.generateDeviceId(deviceInfo);
    const hasActiveSession = await this.sessionService.hasActiveSession(deviceId);

    return {
      deviceId,
      hasActiveSession,
      deviceInfo,
    };
  }

  @Get("verify")
  async verify(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies?.Authentication || req.cookies?.sso_session;
    if (!token) return { loggedIn: false };

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      });

      return {
        loggedIn: true,
        user: {
          id: payload.userId || payload.sub,
          email: payload.email,
          roles: payload.roles,
        },
        accessToken: token,
      };
    } catch {
      return { loggedIn: false, message: "Invalid or expired token" };
    }
  }

  // --- Helper methods for encrypted cookie SSO ---
  private async createEncryptedSSOSession(user: User, res: Response) {
    const tokens = await this.authService.generateTokens(user);
    const encryptedToken = this.encryptToken(tokens.accessToken);
    const isProd = this.configService.get("NODE_ENV") === "production";

    res.cookie("sso_token", encryptedToken, {
      httpOnly: true,
      secure: isProd,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: isProd ? "none" : "lax",
      path: "/",
      // no domain set for local/dev; set your real domain in prod if needed
    });
  }

  private clearEncryptedSSOCookie(res: Response) {
    // Clear without domain to match how it was set above
    res.clearCookie("sso_token", { path: "/" });
  }

  private encryptToken(token: string): string {
    const crypto = require("crypto");
    const algorithm = "aes-256-gcm";

    const encryptionKey =
      this.configService.get("SSO_ENCRYPTION_KEY") || "dev-encryption-key-32-chars-long!";
    const key = crypto.scryptSync(encryptionKey, "salt", 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(token, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
    }

  private decryptToken(encryptedToken: string): string {
    const crypto = require("crypto");
    const algorithm = "aes-256-gcm";

    const [ivHex, authTagHex, encrypted] = encryptedToken.split(":");
    if (!ivHex || !authTagHex || !encrypted) {
      throw new UnauthorizedException("Invalid encrypted token format");
    }

    const encryptionKey =
      this.configService.get("SSO_ENCRYPTION_KEY") || "dev-encryption-key-32-chars-long!";
    const key = crypto.scryptSync(encryptionKey, "salt", 32);
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  private async getUserFromToken(token: string) {
    const payload = this.jwtService.verify(token, {
      secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
    });

    const user = await this.usersService.getUser({ _id: payload.userId });
    if (!user) throw new UnauthorizedException("User not found");

    return {
      userId: user._id.toString(), // <-- string
      email: user.email,
    };
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }
}
