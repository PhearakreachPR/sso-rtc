// src/auth/auth.service.ts - Enhanced with encrypted SSO
import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { compare, hash } from "bcryptjs";
import { Response } from "express";
import { Types } from "mongoose";
import { User } from "../users/schema/user.schema";
import { UsersService } from "../users/users.service";
import { TokenPayload } from "./token-payload.interface";
import { DeviceInfo } from "src/interfaces/device-info.interface";
import { SessionService } from "./services/session.service";
import { createUserRequest } from "src/users/dto/create-user.request";

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
      // Use the existing create method which already handles validation and hashing
      const newUser = await this.usersService.create(createUserDto);
      return newUser;
    } catch (error) {
      // Re-throw known errors or wrap unknown errors
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new BadRequestException("Failed to create user: " + error.message);
    }
  }

  // Register with password confirmation
  async registerWithConfirmation(registerDto: RegisterDto): Promise<any> {
    const { email, password, confirmPassword, firstName, lastName } = registerDto;

    // Validate password confirmation
    if (password !== confirmPassword) {
      throw new BadRequestException("Passwords do not match");
    }

    // Create user request object
    const createUserDto: createUserRequest = {
      email,
      password,
      firstName,
      lastName
    };

    return this.register(createUserDto);
  }

  // ----------------- LOGIN -----------------
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

      // Set encrypted SSO cookie for cross-site access
      this.setEncryptedSSOCookie(response, accessToken);

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

      // For refresh tokens, verify the stored hash
      if (type === "refresh") {
        const userObj = this.toPlainObject(user);
        if (!userObj.refreshToken || !(await compare(token, userObj.refreshToken))) {
          throw new UnauthorizedException("Invalid refresh token");
        }
      }

      // Generate new tokens and login
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

      const userObj = this.toPlainObject(dbUser);
      if (!userObj.refreshToken) {
        throw new UnauthorizedException("Refresh token not found");
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

  // Verify refresh token
  async verifyRefreshToken(refreshToken: string, userId: string): Promise<any> {
    try {
      const user = await this.usersService.findOneById(userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }

      const userObj = this.toPlainObject(user);
      if (!userObj.refreshToken) {
        throw new UnauthorizedException("Refresh token not found");
      }

      const isTokenValid = await compare(refreshToken, userObj.refreshToken);
      if (!isTokenValid) {
        throw new UnauthorizedException("Invalid refresh token");
      }

      return user;
    } catch (error) {
      throw new UnauthorizedException("Refresh token verification failed");
    }
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
      // Fallback for plain objects
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

  // ----------------- TOKEN / SSO SUPPORT -----------------
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

  getAccessTokenExpiration(): string {
    return this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS");
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
      // You can implement actual logging to database here
      // Example: await this.deviceAccessModel.create({ userId, ...deviceInfo });
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
    // You can make this dynamic by fetching from database
    return [
      { domain: "localhost" }, 
      { domain: "localhost:3000" }, 
      { domain: "localhost:3001" }, 
      { domain: "localhost:3002" }, 
      { domain: "127.0.0.1" },
      { domain: "127.0.0.1:3001" },
      { domain: "127.0.0.1:3002" },
      { domain: "127.0.0.1:5500" },
      { domain: "127.0.0.1:5501" },
      {domain:  "localhost:5000"},
      {domain:  "localhost:60000"}
    ];
  }

  async getAllowedDomains(): Promise<string[]> {
    const sites = await this.getAllowedReturnWebsites();
    return sites.map(s => s.domain);
  }

  // Token verification
  async verifyAccessToken(token: string): Promise<boolean> {
    try {
      const payload = this.jwtService.verify(token, { 
        secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET") 
      });
      const user = await this.usersService.findOneById(payload.userId);
      if (!user) return false;
      
      const userObj = this.toPlainObject(user);
      return !!(user && userObj.isActive !== false);
    } catch (error) {
      return false;
    }
  }

  // General token verification
  async verify(token: string) {
    try {
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.getOrThrow("JWT_ACCESS_TOKEN_SECRET")
      });
      
      const user = await this.usersService.findOneById(decoded.userId);
      if (!user) {
        throw new UnauthorizedException("User not found");
      }

      const userObj = this.toPlainObject(user);
      const { password, refreshToken, ...safeUser } = userObj;
      return { valid: true, user: safeUser };
    } catch (error) {
      throw new UnauthorizedException("Invalid or expired token: " + error.message);
    }
  }

  // ----------------- ENCRYPTED SSO METHODS -----------------

  /**
   * Set encrypted SSO cookie for cross-site authentication
   */
  setEncryptedSSOCookie(response: Response, token: string): void {
    try {
      const encryptedToken = this.encryptToken(token);
      const isProd = this.configService.get('NODE_ENV') === 'production';
      const cookieDomain = this.configService.get('COOKIE_DOMAIN') || (isProd ? '.example.com' : undefined);
      
      response.cookie('sso_token', encryptedToken, {
        httpOnly: true,
        secure: isProd,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        sameSite: isProd ? 'none' : 'lax',
        path: '/',
        domain: cookieDomain
      });
    } catch (error) {
      console.error('Failed to set encrypted SSO cookie:', error);
    }
  }

  /**
   * Clear encrypted SSO cookie
   */
  clearEncryptedSSOCookie(response: Response): void {
    try {
      const isProd = this.configService.get('NODE_ENV') === 'production';
      const cookieDomain = this.configService.get('COOKIE_DOMAIN') || (isProd ? '.example.com' : undefined);
      
      response.clearCookie('sso_token', {
        path: '/',
        domain: cookieDomain
      });
    } catch (error) {
      console.error('Failed to clear encrypted SSO cookie:', error);
    }
  }

  /**
   * Encrypt token for secure storage in cookies
   */
  encryptToken(token: string): string {
    try {
      const crypto = require('crypto');
      const algorithm = 'aes-256-gcm';
      
      const encryptionKey = this.configService.get('SSO_ENCRYPTION_KEY') || 'dev-encryption-key-32-chars-long!';
      const key = crypto.scryptSync(encryptionKey, 'salt', 32);
      const iv = crypto.randomBytes(16);
      
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      let encrypted = cipher.update(token, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
      throw new Error('Token encryption failed: ' + error.message);
    }
  }

  /**
   * Decrypt token from secure cookie
   */
  decryptToken(encryptedToken: string): string {
    try {
      const crypto = require('crypto');
      const algorithm = 'aes-256-gcm';
      
      const [ivHex, authTagHex, encrypted] = encryptedToken.split(':');
      
      if (!ivHex || !authTagHex || !encrypted) {
        throw new Error('Invalid encrypted token format');
      }
      
      const encryptionKey = this.configService.get('SSO_ENCRYPTION_KEY') || 'dev-encryption-key-32-chars-long!';
      const key = crypto.scryptSync(encryptionKey, 'salt', 32);
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new UnauthorizedException('Token decryption failed: ' + error.message);
    }
  }

  /**
   * Check if user has valid encrypted SSO session
   */
  async checkEncryptedSSOSession(encryptedToken: string): Promise<any> {
    try {
      const token = this.decryptToken(encryptedToken);
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

  // ----------------- LOGOUT -----------------
  async logout(userId: string, response?: Response): Promise<void> {
    try {
      // Clear refresh token from database
      await this.usersService.updateUser(
        { _id: new Types.ObjectId(userId) },
        { $unset: { refreshToken: 1 } }
      );

      // Clear encrypted SSO cookie if response provided
      if (response) {
        this.clearEncryptedSSOCookie(response);
      }
    } catch (error) {
      console.error("Logout error:", error);
    }
  }

  // Logout from all devices
  async logoutAll(userId: string, response?: Response): Promise<void> {
    try {
      // Clear refresh token and invalidate all sessions
      await this.usersService.updateUser(
        { _id: new Types.ObjectId(userId) },
        { $unset: { refreshToken: 1 } }
      );
      
      // Invalidate all user sessions if session service supports it
      if (this.sessionService.invalidateAllUserSessions) {
        await this.sessionService.invalidateAllUserSessions(userId);
      }

      // Clear encrypted SSO cookie if response provided
      if (response) {
        this.clearEncryptedSSOCookie(response);
      }
    } catch (error) {
      console.error("Logout all error:", error);
    }
  }

  // ----------------- PASSWORD MANAGEMENT -----------------
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
          $unset: { refreshToken: 1 } // Logout from all devices
        }
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new BadRequestException("Failed to change password: " + error.message);
    }
  }

  // Reset password (you'd typically send this via email)
  async resetPassword(email: string, newPassword: string): Promise<void> {
    try {
      const user = await this.usersService.findByEmail(email.toLowerCase().trim());
      if (!user) {
        // Don't reveal if user exists or not
        return;
      }

      const hashedNewPassword = await hash(newPassword, 12);
      await this.usersService.updateUser(
        { _id: user._id },
        { 
          $set: { password: hashedNewPassword },
          $unset: { refreshToken: 1 } // Logout from all devices
        }
      );
    } catch (error) {
      console.error("Password reset error:", error);
    }
  }
}