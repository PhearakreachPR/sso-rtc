// src/auth/auth.service.ts - Simplified without encryption
import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { compare, hash } from "bcryptjs";
import { Response } from "express";
import { Types } from "mongoose";
import { User } from "../users/schema/user.schema";
import { UsersService } from "../users/users.service";
import { DeviceInfo } from "src/interfaces/device-info.interface";
import { SessionService } from "./services/session.service";
import { createUserRequest } from "src/users/dto/create-user.request";
import { TokenPayload } from "src/interfaces/token-payload";

interface RegisterDto {
  email: string;
  password: string;
  confirmPassword: string;
  firstName?: string;
  lastName?: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
  ) {}

  // ----------------- REGISTER -----------------
  async register(createUserDto: createUserRequest): Promise<any> {
    try {
      const newUser = await this.usersService.create(createUserDto);
      return newUser;
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new BadRequestException("Failed to create user: " + error.message);
    }
  }

  // Register with password confirmation
  async registerWithConfirmation(registerDto: RegisterDto): Promise<any> {
    const { email, password, confirmPassword, firstName, lastName } = registerDto;

    if (password !== confirmPassword) {
      throw new BadRequestException("Passwords do not match");
    }

    const createUserDto: createUserRequest = {
      email,
      password,
      firstName,
      lastName
    };

    return this.register(createUserDto);
  }

  // ----------------- LOGIN (like PHP setcookie) -----------------
  async login(user: any, response: Response, deviceInfo?: DeviceInfo) {
    try {
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
      sameSite: "none",  // important for cross-site
      path: "/",
      expires: expiresAccessToken,
    });

    response.cookie("Refresh", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "none",  // important
      path: "/auth/refresh",
      expires: expiresRefreshToken,
    });
      // Set encrypted SSO cookie for cross-site access


      // Log device access if provided
      if (deviceInfo) {
        await this.logDeviceAccess(user._id.toString(), {
          deviceInfo: JSON.stringify(deviceInfo),
          accessTime: new Date(),
          ipAddress: deviceInfo.ipAddress || 'unknown'
        });
      }

      return { 
        user: await this.getSanitizedUser(user._id.toString()), 
        accessToken, 
        refreshToken 
      };
    } catch (error) {
      throw new UnauthorizedException("Login failed: " + error.message);
    }
  }
  // ----------------- TOKEN LOGIN -----------------
  async loginWithToken(token: string, type: "access" | "refresh", response: Response) {
    try {
      let payload: TokenPayload;
      if (type === "access") {
        payload = this.jwtService.verify(token, { 
          secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") 
        });
      } else {
        payload = this.jwtService.verify(token, { 
          secret: this.configService.getOrThrow("JWT_REFRESH_TOKEN_SECRET") 
        });
      }

      const user = await this.usersService.findOneById(payload.userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }

      if (type === "refresh") {
        const userObj = this.toPlainObject(user);
        if (!userObj.refreshToken || !(await compare(token, userObj.refreshToken))) {
          throw new UnauthorizedException("Invalid refresh token");
        }
      }

      return await this.login(user, response);
    } catch (error) {
      throw new UnauthorizedException("Invalid or expired token: " + error.message);
    }
  }

  // ----------------- REFRESH -----------------
  async refresh(user: any, response: Response) {
    try {
      const dbUser = await this.usersService.findOneById(user._id.toString());
      if (!dbUser) {
        throw new UnauthorizedException("User not found");
      }

      return await this.login(dbUser, response);
    } catch (error) {
      throw new UnauthorizedException("Token refresh failed: " + error.message);
    }
  }

  // ----------------- VERIFY USER -----------------
  async verifyUser(email: string, password: string): Promise<any> {
    try {
      const user = await this.usersService.findByEmail(email.toLowerCase().trim());
      if (!user) {
        throw new UnauthorizedException("Invalid credentials");
      }

      const userObj = this.toPlainObject(user);
      const isPasswordValid = await compare(password, userObj.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException("Invalid credentials");
      }

      if (userObj.isActive === false) {
        throw new UnauthorizedException("Account is deactivated");
      }

      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException("Authentication failed");
    }
  }
async verifyRefreshToken(refreshToken: string, userId: string) {
  const user = await this.usersService.findOneById(userId);
  if (!user) {
    throw new Error("User not found");
  }

  const userObj = this.toPlainObject(user);

  // Check if user has a valid refresh token
  if (!userObj.refreshToken) {
    throw new Error("No refresh token found for user");
  }

  // Compare the provided token with the stored hashed token
  const isValid = await compare(refreshToken, userObj.refreshToken);
  if (!isValid) {
    throw new Error("Invalid refresh token");
  }

  return userObj;
}
  // Validate user for Passport local strategy
  async validateUser(email: string, password: string): Promise<any> {
    try {
      const user = await this.verifyUser(email, password);
      if (user) {
        const userObj = this.toPlainObject(user);
        const { password: pwd, refreshToken, ...result } = userObj;
        return result;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  // Helper method to safely convert to plain object
  private toPlainObject(user: any): any {
    if (!user) return null;
    
    if (typeof user.toObject === 'function') {
      return user.toObject();
    } else if (typeof user.toJSON === 'function') {
      return user.toJSON();
    } else {
      return JSON.parse(JSON.stringify(user));
    }
  }

  // Get sanitized user data
  private async getSanitizedUser(userId: string) {
    try {
      const user = await this.usersService.findOneById(userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }
      
      const userObject = this.toPlainObject(user);
      const { password, refreshToken, ...sanitizedUser } = userObject;
      return sanitizedUser;
    } catch (error) {
      throw new UnauthorizedException("Failed to get user data");
    }
  }

  // ----------------- TOKEN SUPPORT -----------------
  async generateTokens(user: any) {
    try {
      const payload: TokenPayload = { userId: user._id.toString() };
      
      const accessToken = this.jwtService.sign(payload, { 
        secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET"), 
        expiresIn: `${this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")}ms` 
      });
      
      const refreshToken = this.jwtService.sign(payload, { 
        secret: this.configService.getOrThrow("JWT_REFRESH_TOKEN_SECRET"), 
        expiresIn: `${this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")}ms` 
      });
      
      return { accessToken, refreshToken };
    } catch (error) {
      throw new Error("Failed to generate tokens: " + error.message);
    }
  }

  async getUserFromToken(token: string): Promise<any> {
    try {
      const payload = this.jwtService.verify(token, { 
        secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") 
      });
      
      const user = await this.usersService.findOneById(payload.userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }
      
      const userObj = this.toPlainObject(user);
      return { 
        userId: user._id, 
        email: userObj.email,
        firstName: userObj.firstName || null,
        lastName: userObj.lastName || null,
        roles: userObj.roles || []
      };
    } catch (error) {
      throw new UnauthorizedException("Invalid token: " + error.message);
    }
  }

  // Device access logging
  async logDeviceAccess(userId: string, deviceInfo: { 
    deviceInfo?: string; 
    appName?: string; 
    accessTime: Date; 
    ipAddress?: string 
  }) {
    try {
      console.log(`Device access logged for user ${userId}:`, deviceInfo);
    } catch (error) {
      console.error("Failed to log device access:", error);
    }
  }

  // Return URL validation
  async validateReturnUrl(returnUrl: string): Promise<string | null> {
    if (!returnUrl) return null;
    
    try {
      const url = new URL(returnUrl);
      const allowedWebsites = await this.getAllowedReturnWebsites();
      const isAllowed = allowedWebsites.some(a => 
        url.hostname === a.domain || 
        url.hostname.endsWith("." + a.domain)
      );
      return isAllowed ? returnUrl : null;
    } catch (error) {
      console.error("Invalid return URL:", error);
      return null;
    }
  }

  private async getAllowedReturnWebsites(): Promise<Array<{ domain: string }>> {
    return [
      { domain: "localhost" }, 
      { domain: "localhost:3000" }, 
      { domain: "localhost:5000" },    // Site 1
      { domain: "localhost:60000" },   // Site 2
      { domain: "127.0.0.1" },
      { domain: "127.0.0.1:5000" },
      { domain: "127.0.0.1:60000" },
    ];
  }

  // Simple token verification (no encryption)
  async verifyAccessToken(token: string): Promise<boolean> {
    try {
      const payload = this.jwtService.verify(token, { 
        secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") 
      });
      
      const user = await this.usersService.findOneById(payload.userId); 
      if (!user) {
        return false;
      }
      
      const userObj = this.toPlainObject(user);
      const isActive = userObj.isActive !== false;
      
      return !!(user && isActive);
    } catch (error) {
      return false;
    }
  }

  // Check if user has valid SSO session (simple token check)
  async checkSSOSession(token: string): Promise<any> {
    try {
      const isValid = await this.verifyAccessToken(token);
      
      if (isValid) {
        const userInfo = await this.getUserFromToken(token);
        return {
          valid: true,
          user: userInfo,
          token: token
        };
      }
      
      return { valid: false };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  // ----------------- LOGOUT (like PHP setcookie with past expiration) -----------------
  async logout(userId: string, response?: Response): Promise<void> {
    try {
        // Clear refresh token in DB
        await this.usersService.updateUser(
            { _id: new Types.ObjectId(userId) },
            { $unset: { refreshToken: 1 } }
        );

        if (response) {
            response.clearCookie('Authentication', { path: '/' });
            response.clearCookie('Refresh', { path: '/' });
        }
    } catch (error) {
        console.error("Logout error:", error);
    }
}

  // Password management
  async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
    try {
      const user = await this.usersService.findOneById(userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }

      const userObj = this.toPlainObject(user);
      const isOldPasswordValid = await compare(oldPassword, userObj.password);
      if (!isOldPasswordValid) {
        throw new UnauthorizedException("Current password is incorrect");
      }

      const hashedNewPassword = await hash(newPassword, 12);
      await this.usersService.updateUser(
        { _id: new Types.ObjectId(userId) },
        { 
          $set: { password: hashedNewPassword },
          $unset: { refreshToken: 1 }
        }
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new BadRequestException("Failed to change password: " + error.message);
    }
  }
}