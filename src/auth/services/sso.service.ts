// src/auth/services/sso.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';
import { EncryptionService } from './encryption.service';
import { AuthService } from '../auth.service';
import { UsersService } from '../../users/users.service';

interface SSOTokenPayload {
  userId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  roles?: string[];
  exp: number; // expiration timestamp
  iat: number; // issued at timestamp
  domain: string; // originating domain
}

@Injectable()
export class SSOService {
  private readonly SSO_COOKIE_NAME = 'sso_session';
  private readonly SSO_COOKIE_DOMAIN = '.localhost'; // Change to your domain
  private readonly SSO_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

  constructor(
    private readonly encryptionService: EncryptionService,
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService
  ) {}

  // Create SSO session after successful login
  async createSSOSession(user: any, response: Response, originDomain: string): Promise<void> {
    const payload: SSOTokenPayload = {
      userId: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: user.roles || [],
      exp: Date.now() + this.SSO_TOKEN_EXPIRY,
      iat: Date.now(),
      domain: originDomain
    };

    const encryptedToken = this.encryptionService.encryptToken(payload);

    // Set SSO cookie with domain scope
    response.cookie(this.SSO_COOKIE_NAME, encryptedToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax', // Important for cross-site SSO
      domain: this.SSO_COOKIE_DOMAIN, // This allows sharing across subdomains
      expires: new Date(Date.now() + this.SSO_TOKEN_EXPIRY),
      path: '/'
    });
  }

  // Check if user has valid SSO session
  async checkSSOSession(request: Request): Promise<SSOTokenPayload | null> {
    try {
      const ssoToken = request.cookies?.[this.SSO_COOKIE_NAME];
      
      if (!ssoToken) {
        return null;
      }

      const payload = this.encryptionService.decryptToken(ssoToken);
      
      // Check if token is expired
      if (payload.exp < Date.now()) {
        return null;
      }

      // Verify user still exists and is active
      const user = await this.usersService.findOneById(payload.userId);
      if (!user) {
        return null;
      }

      const userObj = (user as any).toObject ? (user as any).toObject() : user;
      if (!userObj.isActive) {
        return null;
      }

      return payload;
    } catch (error) {
      console.error('SSO session check failed:', error);
      return null;
    }
  }

  // Auto-login user from SSO session
  async autoLoginFromSSO(
    request: Request, 
    response: Response, 
    returnUrl?: string
  ): Promise<{ success: boolean; redirectUrl?: string; user?: any; tokens?: any }> {
    try {
      const ssoPayload = await this.checkSSOSession(request);
      
      if (!ssoPayload) {
        return { success: false };
      }

      // Get fresh user data
      const user = await this.usersService.findOneById(ssoPayload.userId);
      if (!user) {
        return { success: false };
      }

      // Generate new JWT tokens for this session
      const tokens = await this.authService.generateTokens(user);
      
      // Set JWT cookies for the current domain
      const expiresAccessToken = new Date(Date.now() + parseInt(this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")));
      const expiresRefreshToken = new Date(Date.now() + parseInt(this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")));
      
      const isProd = this.configService.get("NODE_ENV") === "production";
      
      response.cookie("Authentication", tokens.accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        expires: expiresAccessToken,
      });
      
      response.cookie("Refresh", tokens.refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        path: "/auth/refresh",
        expires: expiresRefreshToken,
      });

      // Update user's refresh token in database
      await this.usersService.updateUser(
        { _id: user._id },
        { $set: { refreshToken: await this.authService['hash'](tokens.refreshToken, 10) } }
      );

      // Create redirect URL if provided
      let redirectUrl = returnUrl;
      if (redirectUrl) {
        const url = new URL(redirectUrl);
        url.searchParams.set('access_token', tokens.accessToken);
        url.searchParams.set('user_id', user._id.toString());
        redirectUrl = url.toString();
      }

      const sanitizedUser = await this.authService['getSanitizedUser'](user._id.toString());

      return {
        success: true,
        redirectUrl,
        user: sanitizedUser,
        tokens
      };
    } catch (error) {
      console.error('Auto-login from SSO failed:', error);
      return { success: false };
    }
  }

  // Clear SSO session
  async clearSSOSession(response: Response): Promise<void> {
    response.clearCookie(this.SSO_COOKIE_NAME, {
      domain: this.SSO_COOKIE_DOMAIN,
      path: '/'
    });
  }

  // Validate domain is allowed for SSO
  async validateSSODomain(domain: string): Promise<boolean> {
    const allowedDomains = await this.getAllowedSSODomains();
    return allowedDomains.some(allowed => 
      domain === allowed || 
      domain.endsWith('.' + allowed)
    );
  }

  private async getAllowedSSODomains(): Promise<string[]> {
    // You can store this in database or config
    return [
      'localhost',
      'localhost:3000',
      'localhost:3001',
      'localhost:3002',
      '127.0.0.1:5500',
      '127.0.0.1:5501',
      // Add your production domains here
      // 'app1.yourdomain.com',
      // 'app2.yourdomain.com'
    ];
  }

  // Generate SSO login URL
  generateSSOLoginUrl(targetDomain: string, returnUrl?: string): string {
    const ssoBaseUrl = this.configService.get('SSO_SERVER_URL') || 'http://localhost:3000';
    const loginUrl = new URL('/auth/sso-check', ssoBaseUrl);
    
    if (returnUrl) {
      loginUrl.searchParams.set('returnUrl', returnUrl);
    }
    
    loginUrl.searchParams.set('targetDomain', targetDomain);
    
    return loginUrl.toString();
  }

  // Refresh SSO session (extend expiry)
  async refreshSSOSession(request: Request, response: Response): Promise<boolean> {
    try {
      const ssoPayload = await this.checkSSOSession(request);
      
      if (!ssoPayload) {
        return false;
      }

      // Create new SSO session with extended expiry
      const user = await this.usersService.findOneById(ssoPayload.userId);
      if (!user) {
        return false;
      }

      await this.createSSOSession(user, response, ssoPayload.domain);
      return true;
    } catch (error) {
      console.error('SSO session refresh failed:', error);
      return false;
    }
  }
}