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
import type { Request, Response } from "express";
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
import { EncryptionService } from './services/encryption.service';

// DTOs
export class LoginDto {
  email: string;
  password: string;
  returnUrl?: string;
}

class TokenLoginDto {
  token: string;
  type: "access" | "refresh";
}

interface CustomRequest extends Request {
  deviceInfo?: DeviceInfo;
  cookies: Record<string, string>;
}

@Controller("auth")
export class AuthController {
  [x: string]: any;
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
    private readonly ssoService: SSOService,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {}
  // --- Register user ---
  @Post("register")
  async register(
    @Body() registerDto: createUserRequest,
    @Res() res: Response,
    @Req() req: Request
  ) {
    try {
      const user = await this.authService.register(registerDto);
      
      // Auto-login after successful registration
      const result = await this.authService.login(user, res);

      return res.json({
        message: "User registered successfully",
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken
      });
    } catch (error) {
      return res.status(400).json({
        message: "Registration failed",
        error: error.message
      });
    }
  }

  // --- Enhanced SSO Check (like PHP session/cookie check) ---
// --- Enhanced SSO Check with optional auto-login ---
@Get("sso-check")
async ssoCheck(
  @Req() req: CustomRequest,
  @Res() res: Response,
  @Query("returnUrl") returnUrl?: string,
  @Query("autoLogin") autoLogin?: string,
) {
  try {
    // Only proceed if autoLogin is explicitly true
    if (autoLogin !== 'true') {
      return res.json({
        success: false,
        authenticated: false,
        message: "Auto-login not enabled"
      });
    }

    const token = req.cookies?.sso_token;
    if (!token) {
      return res.json({
        success: false,
        authenticated: false,
        message: "No SSO token found"
      });
    }

    // Validate token
    const isValid = await this.authService.verifyAccessToken(token);
    if (!isValid) {
      return res.json({
        success: false,
        authenticated: false,
        message: "Invalid token"
      });
    }

    const userInfo = await this.authService.getUserFromToken(token);
    
    if (returnUrl) {
      const redirectUrl = `${returnUrl}?token=${token}&autoLogin=true`;
      return res.json({
        success: true,
        authenticated: true,
        user: userInfo,
        redirectUrl: redirectUrl,
        message: "Auto-login successful"
      });
    }

    return res.json({
      success: true,
      authenticated: true,
      user: userInfo
    });

  } catch (error) {
    return res.json({
      success: false,
      authenticated: false,
      message: "SSO check failed"
    });
  }
}


  // --- Login page ---
  // GET route to show login page
  @Get('login')
  @Render('login')
  showLoginPage(@Query('returnUrl') returnUrl?: string, @Query('error') error?: string) {
    return { returnUrl, error };
  }

  // POST route for login - returns JSON or redirects based on returnUrl
  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(
    @CurrentUser() user: any,
    @Body('returnUrl') returnUrl: string,
    @Res({ passthrough: false }) res: Response,
  ) {
    try {
      const result = await this.authService.login(user, res);
      
      if (returnUrl) {
        // SSO redirect with tokens
        const redirectUrl = `${returnUrl}?accessToken=${result.accessToken}&refreshToken=${result.refreshToken}&user_id=${result.user._id}`;
        return res.redirect(redirectUrl);
      } 
      return res.json(result);
    } catch (error) {
      // Redirect back to login with error
      const errorUrl = `/auth/login${returnUrl ? `?returnUrl=${encodeURIComponent(returnUrl)}` : ''}`;
      return res.redirect(`${errorUrl}&error=${encodeURIComponent('Login failed')}`);
    }
  }


  // --- Login with LocalAuthGuard ---
//  @Post("login")
//   @UseGuards(LocalAuthGuard)
//   async login(
//     @CurrentUser() user: User,
//     @Body("returnUrl") returnUrl: string,
//     @Res() res: Response,
//   ) {
//     try {
//       const result = await this.authService.login(user, res);
      
//       if (returnUrl) {
//         // Simple redirect with token in URL
//         const redirectUrl = `${returnUrl}?token=${result.accessToken}&user_id=${result.user._id}`;
//         return res.redirect(redirectUrl);
//       }

//       return res.json(result);
//     } catch (error) {
//       const loginUrl = `/auth/login?error=${encodeURIComponent("Login failed")}`;
//       if (returnUrl) {
//         return res.redirect(`${loginUrl}&returnUrl=${encodeURIComponent(returnUrl)}`);
//       }
//       return res.redirect(loginUrl);
//     }
//   }
// @Post("login")
// @UseGuards(LocalAuthGuard)
// async login(
//   @CurrentUser() user: User,
//   @Body("returnUrl") returnUrl: string,
//   @Res() res: Response,
// ) {
//   try {
//     // Use generateTokens instead of generateAccessToken
//     const tokens = await this.authService.generateTokens(user);
//     const accessToken = tokens.accessToken;

//     const isProd = process.env.NODE_ENV === 'production';
//     res.cookie('sso_token', accessToken, {
//       httpOnly: true,
//       secure: isProd,
//       sameSite: isProd ? 'none' : 'lax',
//       maxAge: 1000 * 60 * 60,
//       path: '/',
//     });

//     if (returnUrl) {
//       return res.redirect(returnUrl);
//     }

//     return res.json({
//       success: true,
//       message: "Logged in successfully",
//       user: {
//         id: user._id,
//         email: user.email,
//       },
//     });
//   } catch (error) {
//     console.error("Login error:", error);
//     return res.status(401).json({ success: false, message: "Login failed" });
//   }
// }

  // --- Enhanced SSO Status ---
  // @Get("sso-status")
  // async checkSSOStatus(@Req() req: CustomRequest) {
  //   try {
  //     // Check encrypted cookie first (PHP-style)
  //     const encryptedToken = req.cookies?.sso_token;
      
  //     if (encryptedToken) {
  //       try {
  //         // Use EncryptionService directly to decrypt the JWT token string
  //         const token = this.encryptionService.decryptString(encryptedToken);
  //         const payload = this.jwtService.verify(token, {
  //           secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
  //         });
          
  //         const user = await this.usersService.getUser({ _id: payload.userId });
          
  //         if (user) {
  //           return {
  //             isLoggedIn: true,
  //             user: {
  //               id: user._id,
  //               email: user.email,
  //             },
  //             expiresAt: new Date(payload.exp * 1000),
  //             source: 'encrypted_cookie'
  //           };
  //         }
  //       } catch (error) {
  //         console.warn('Invalid encrypted SSO token:', error.message);
  //       }
  //     }

  //     // Fallback to original SSO service
  //     const ssoPayload = await this.ssoService.checkSSOSession(req);
      
  //     if (ssoPayload) {
  //       return {
  //         isLoggedIn: true,
  //         user: {
  //           id: ssoPayload.userId,
  //           email: ssoPayload.email,
  //           firstName: ssoPayload.firstName,
  //           lastName: ssoPayload.lastName,
  //           roles: ssoPayload.roles
  //         },
  //         expiresAt: new Date(ssoPayload.exp),
  //         source: 'sso_service'
  //       };
  //     } else {
  //       return {
  //         isLoggedIn: false
  //       };
  //     }
  //   } catch (error) {
  //     return {
  //       isLoggedIn: false,
  //       error: error.message
  //     };
  //   }
  // }
// @Post("login")
// @UseGuards(LocalAuthGuard)
// async login(
//   @CurrentUser() user: User,
//   @Body("returnUrl") returnUrl: string,
//   @Res() res: Response,
// ) {
//   try {
//     const tokens = await this.authService.generateTokens(user);

//     // Set cookies
//     res.cookie('Authentication', tokens.accessToken, { httpOnly: true, path: '/' });
//     res.cookie('Refresh', tokens.refreshToken, { httpOnly: true, path: '/' });
//     res.cookie('sso_token', tokens.accessToken, { 
//       httpOnly: false, 
//       path: '/',
//       sameSite: 'none',
//       secure: process.env.NODE_ENV === 'production'
//     });

//     if (returnUrl) {
//       // PROPERLY format the redirect URL with ALL required parameters
//       const url = new URL(returnUrl);
//       url.searchParams.set('token', tokens.accessToken);
//       url.searchParams.set('user_id', user._id.toString()); // ← MAKE SURE THIS IS INCLUDED
//       url.searchParams.set('autoLogin', 'true');
      
//       console.log('Redirecting to:', url.toString());
//       return res.redirect(url.toString());
//     }

//     return res.json({ user, ...tokens });
//   } catch (error) {
//     console.error('Login error:', error);
//     return res.redirect(`/auth/login?error=${encodeURIComponent("Login failed")}`);
//   }
// }
@Get("user-info")
async getUserInfo(@Query('token') token: string) {
  try {
    const payload = this.jwtService.verify(token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
    });
    
    const user = await this.usersService.findOneById(payload.userId);
    if (!user) {
      return { error: "User not found" };
    }
    
    return {
      id: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName
    };
  } catch (error) {
    return { error: "Invalid token" };
  }
}
  @Post("sso-login")
  async ssoAutoLogin(
    @Req() req: Request,
    @Res() res: Response,
    @Body("returnUrl") returnUrl?: string
  ) {
    try {
      const result = await this.ssoService.autoLoginFromSSO(req, res, returnUrl);
      
      if (result.success) {
        if (returnUrl && result.redirectUrl) {
          return res.redirect(result.redirectUrl);
        } else {
          return res.json({
            success: true,
            user: result.user,
            accessToken: result.tokens?.accessToken,
            refreshToken: result.tokens?.refreshToken
          });
        }
      } else {
        return res.status(401).json({
          success: false,
          message: "No valid SSO session found"
        });
      }
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "SSO auto-login failed",
        error: error.message
      });
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
async verifyTokenForPHP(@Query('token') token: string, @Req() req: Request) {
  console.log('🔐 Token verification request received');
  console.log('Request URL:', req.url);
  console.log('Query parameters:', req.query);
  console.log('HTTP Method:', req.method);
  
  // Handle OPTIONS requests (CORS preflight)
  if (req.method === 'OPTIONS') {
    return { valid: false, message: "Preflight request" };
  }

  if (!token) {
    console.log('❌ No token provided in query parameters');
    console.log('Full request details:', {
      url: req.url,
      method: req.method,
      headers: req.headers,
      query: req.query
    });
    return { valid: false, message: "No token provided" };
  }

  // Remove "Bearer " prefix if present
  if (token.startsWith('Bearer ')) {
    token = token.substring(7);
  }

  try {
    const isValid = await this.authService.verifyAccessToken(token);
    console.log('✅ Token valid:', isValid);
    return { valid: isValid };
  } catch (error) {
    console.log('❌ Token verification failed:', error.message);
    return { valid: false, message: "Token verification failed" };
  }
}
@Get("debug-verify")
async debugVerify(@Query('token') token: string, @Req() req: Request) {
  console.log('=== DEBUG TOKEN VERIFICATION ===');
  
  // Get token from query or header
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    return { error: "No token provided" };
  }

  console.log('Token received:', token.substring(0, 50) + '...');
  
  try {
    // 1. First test pure JWT verification
    const secret = this.configService.get('JWT_ACCESS_TOKEN_SECRET');
    console.log('JWT Secret available:', !!secret);
    
    const payload = this.jwtService.verify(token, { secret });
    console.log('✅ Pure JWT verification successful:', payload);
    
    // 2. Test user lookup
    const user = await this.usersService.findOneById(payload.userId);
    console.log('User found:', !!user);
    
    if (!user) {
      return { 
        valid: false, 
        reason: "User not found", 
        userId: payload.userId,
        jwtValid: true 
      };
    }
    
    // 3. Check user status
    const userObj = this.toPlainObject(user);
    const isActive = userObj.isActive !== false;
    console.log('User active:', isActive);
    
    if (!isActive) {
      return { 
        valid: false, 
        reason: "User not active", 
        userId: payload.userId,
        jwtValid: true,
        userFound: true
      };
    }
    
    return { 
      valid: true, 
      user: { id: user._id, email: userObj.email, active: isActive },
      jwtValid: true,
      userFound: true,
      userActive: true
    };
    
  } catch (error) {
    console.log('❌ Verification failed:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return { 
        valid: false, 
        reason: "JWT Error", 
        error: error.message,
        possibleCause: "Secret mismatch or invalid token format"
      };
    }
    
    if (error.name === 'TokenExpiredError') {
      return { 
        valid: false, 
        reason: "Token Expired", 
        error: error.message,
        expiredAt: error.expiredAt
      };
    }
    
    return { 
      valid: false, 
      reason: "Other Error", 
      error: error.message 
    };
  }
}
@Get("check-cookie")
checkCookie(@Req() req: Request) {
  const ssoToken = req.cookies?.sso_token;
  const authToken = req.cookies?.Authentication;
  
  console.log('🍪 SSO Token from cookie:', ssoToken);
  console.log('📏 SSO Token length:', ssoToken?.length);
  console.log('🔢 SSO Token parts:', ssoToken?.split('.').length);
  
  console.log('🍪 Auth Token from cookie:', authToken);
  console.log('📏 Auth Token length:', authToken?.length);
  console.log('🔢 Auth Token parts:', authToken?.split('.').length);
  
  return {
    ssoToken: {
      exists: !!ssoToken,
      length: ssoToken?.length,
      parts: ssoToken?.split('.').length,
      preview: ssoToken ? ssoToken.substring(0, 50) + '...' : null
    },
    authToken: {
      exists: !!authToken,
      length: authToken?.length,
      parts: authToken?.split('.').length,
      preview: authToken ? authToken.substring(0, 50) + '...' : null
    }
  };
}
@Get("inspect-token")
inspectToken(@Query('token') token: string, @Req() req: Request) {
  // Get token from header if not in query
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    return { error: "No token provided" };
  }

  console.log('=== TOKEN INSPECTION ===');
  console.log('Full token:', token);
  console.log('Token length:', token.length);
  console.log('Token parts:', token.split('.').length);
  
  // Check if it looks like a JWT
  const parts = token.split('.');
  const isJWTFormat = parts.length === 3;
  
  let header, payload;
  try {
    if (parts.length >= 1) header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (parts.length >= 2) payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
  } catch (e) {
    console.log('Failed to parse JWT parts:', e.message);
  }

  return {
    tokenLength: token.length,
    partsCount: parts.length,
    isJWTFormat: isJWTFormat,
    header: header,
    payload: payload,
    first50Chars: token.substring(0, 50),
    last50Chars: token.substring(token.length - 50)
  };
}
@Get("  generate-test-token")
generateTestToken() {
  const payload = { 
    userId: '68b931b5321c0629a7881546', 
    email: 'test@example.com',
    timestamp: Date.now()
  };
  
  const token = this.jwtService.sign(payload, {
    secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
    expiresIn: '1h'
  });
  
  console.log('Generated token length:', token.length);
  console.log('Generated token parts:', token.split('.').length);
  
  return {
    token: token,
    length: token.length,
    parts: token.split('.').length,
    header: JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString()),
    payload: JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())
  };
}
  // --- Enhanced token checking ---
   @Get("check-token")
  async checkToken(@Query('token') token: string) {
    if (!token) {
      return { valid: false, message: "No token provided" };
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
      });
      
      const user = await this.usersService.getUser({ _id: payload.userId });
      
      if (!user) {
        return { valid: false, message: "User not found" };
      }
      
      return {
        valid: true,
        user: {
          id: user._id,
          email: user.email,
        },
        message: "Token is valid"
      };
    } catch (error) {
      return { valid: false, message: "Invalid or expired token" };
    }
  }


  // --- Token status ---
  @Get("token-status")
  checkTokenStatus(@Req() req: Request) {
    const token = this.extractTokenFromHeader(req);

    if (!token) {
      return { isLoggedIn: false, message: "No token provided" };
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
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
 @Get("verify")
  async verify(@Req() req: CustomRequest, @Res() res: Response) {
    const token = req.cookies?.Authentication || req.cookies?.sso_session;

    if (!token) {
      return res.status(401).json({ loggedIn: false });
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      });

      return res.json({
        loggedIn: true,
        user: {
          id: payload.userId || payload.sub,
          email: payload.email,
          roles: payload.roles,
        },
        accessToken: token,
      });
    } catch (err) {
      return res.status(401).json({ loggedIn: false, message: "Invalid or expired token" });
    }
  }

// Standard API logout (protected with JWT)
  @UseGuards(JwtAuthGuard)
  @Post("logout")
  async logout(
    @Req() req: any, 
    @Res({ passthrough: true }) res: Response,
    @Query('returnUrl') returnUrl?: string
  ) {
    try {
      const token = this.extractTokenFromHeader(req);
      
      // Invalidate session and tokens
      if (token) {
        await this.sessionService.invalidateSession(token);
      }
      
      // Clear all auth cookies
      res.clearCookie('Authentication');
      res.clearCookie('Refresh');
      res.clearCookie('sso_token');
      
      // If returnUrl provided, redirect without tokens
      if (returnUrl) {
        // Clean the returnUrl by removing any existing token parameters
        const cleanUrl = this.removeTokenParams(returnUrl);
        return res.redirect(cleanUrl);
      }
      
      return { 
        success: true,
        message: "Logged out successfully" 
      };
      
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still attempt to redirect even if error
      if (returnUrl) {
        const cleanUrl = this.removeTokenParams(returnUrl);
        return res.redirect(cleanUrl);
      }
      
      throw new UnauthorizedException('Logout failed');
    }
  }

  private removeTokenParams(url: string): string {
  try {
    const urlObj = new URL(url);
    
    // Remove token-related parameters
    const paramsToRemove = [
      'accessToken', 'refreshToken', 'token', 
      'logout', 'error', 'message'
    ];
    
    paramsToRemove.forEach(param => {
      urlObj.searchParams.delete(param);
    });
    
    // Add logout success parameter
    urlObj.searchParams.set('logout', 'success');
    
    return urlObj.toString();
  } catch (error) {
    // If URL parsing fails, return original URL without obvious token params
    return url
      .replace(/[?&]accessToken=[^&]*/g, '')
      .replace(/[?&]refreshToken=[^&]*/g, '')
      .replace(/[?&]token=[^&]*/g, '')
      + '?logout=success';
  }
}

  // Optional GET logout (for SSO flows / PHP style)
  @Get('logout')
  async logoutGet(@Req() req: Request, @Res() res: Response, @Query('returnUrl') returnUrl?: string) {
    const userId = (req as any).user?.userId; // if JWT guard not used, may be undefined

    if (userId) {
      await this.authService.logout(userId, res);
    } else {
      res.clearCookie('token');
      res.clearCookie('Authentication');
    }

    if (returnUrl) {
      const safeUrl = await this.authService.validateReturnUrl(returnUrl);
      if (safeUrl) {
        return res.redirect(safeUrl);
      }
    }

    return res.json({ message: 'Logged out successfully (GET)' });
  }

// Add these two methods to your AuthController class
// Place them anywhere within the @Controller("auth") class, preferably near your other GET endpoints

// 1. Check current user session (for auto-login detection)
@Get("me")
async getCurrentUser(@Req() req: Request, @Res() res: Response) {
  console.log('🔍 Checking current user session...');
  console.log('Cookies:', req.cookies);
  
  try {
    // Check for authentication token in cookies
    const token = req.cookies?.Authentication || req.cookies?.sso_token;
    
    if (!token) {
      console.log('❌ No auth token found in cookies');
      return res.status(401).json({ authenticated: false });
    }
    
    // Verify the token
    const payload = this.jwtService.verify(token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
    });
    
    console.log('✅ Token verified, payload:', payload);
    
    // Get user details
    const user = await this.usersService.findOneById(payload.userId);
    
    if (!user) {
      console.log('❌ User not found for ID:', payload.userId);
      return res.status(401).json({ authenticated: false });
    }
    
    console.log('✅ User found:', user.email);
    
    return res.json({
      authenticated: true,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      },
      id: user._id.toString() // PHP code expects this at root level too
    });
    
  } catch (error) {
    console.log('❌ Session check failed:', error.message);
    return res.status(401).json({ authenticated: false });
  }
}

// 2. Get fresh tokens for authenticated user
@Get("token")
async getFreshTokens(@Req() req: Request, @Res() res: Response) {
  console.log('🔄 Fresh token request...');
  
  try {
    // Check for existing authentication
    const token = req.cookies?.Authentication || req.cookies?.sso_token;
    
    if (!token) {
      console.log('❌ No auth token for fresh token generation');
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Verify current token
    const payload = this.jwtService.verify(token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
    });
    
    // Get user
    const user = await this.usersService.findOneById(payload.userId);
    
    if (!user) {
      console.log('❌ User not found for fresh tokens');
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Generate fresh tokens using your existing method
    const tokens = await this.authService.generateTokens(user);
    
    console.log('✅ Fresh tokens generated for user:', user.email);
    
    return res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user_id: user._id.toString(),
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
    
  } catch (error) {
    console.log('❌ Fresh token generation failed:', error.message);
    return res.status(401).json({ error: 'Failed to generate fresh tokens' });
  }
}
  // @Get("device-status")
  // async checkDeviceStatus(@Req() req: CustomRequest) {
  //   const deviceInfo = req.deviceInfo;
  //  const deviceId = this.sessionService.generateDeviceId(deviceInfo);
  // const hasActiveSession = await this.sessionService.hasActiveSession(deviceId);

  // return {
  //      deviceId,
  //     hasActiveSession,
  //     deviceInfo,
  //   };
  //  }

 
  // --- Helper methods ---
  // private extractTokenFromHeader(request: Request): string | undefined {
  //   const authHeader = request.headers.authorization;
  //   if (!authHeader) return undefined;
    
  //   const [type, token] = authHeader.split(" ");
  //   // Fix the typo: "Bearer" not "Btoken"
  //   return type === "Bearer" ? token : undefined;
  // }

  // // private getErrorMessage(errorCode?: string): string {
  //   switch (errorCode) {
  //     case '1': return 'Invalid credentials';
  //     case '2': return 'Session expired';
  //     case 'missing_credentials': return 'Please fill in all fields';
  //     case 'invalid_credentials': return 'Invalid email or password';
  //     case 'login_failed': return 'Login failed. Please try again.';
  //     default: return errorCode || '';
  //   }
  // }

  // private getErrorCode(error: any): string {
  //   if (error.message?.includes('Invalid credentials')) {
  //     return '1';
  //   }
  //   if (error.message?.includes('expired')) {
  //     return '2';
  //   }
  //   return 'login_failed';
  // 
}
