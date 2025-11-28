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

export class RegisterDto extends createUserRequest {
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
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
    private readonly ssoService: SSOService,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {}

  // --- Enhanced Register with Role Support ---
  @Post("register")
  async register(
    @Body() registerDto: RegisterDto,
    @Res() res: Response,
    @Req() req: Request
  ) {
    try {
      // Validate role
      const validRoles = ['Admin', 'Teacher', 'Head_Department', 'Student'];
      if (registerDto.role && !validRoles.includes(registerDto.role)) {
        return res.status(400).json({
          message: "Invalid role specified",
          validRoles: validRoles
        });
      }

      // Default to Student if no role specified
      if (!registerDto.role) {
        registerDto.role = 'Student';
      }

      const user = await this.authService.register(registerDto);
      
      // Auto-login after successful registration
      const result = await this.authService.login(user, res);

      return res.json({
        message: "User registered successfully",
        user: result.user,
        role: registerDto.role,
        roles: [registerDto.role], // For compatibility with Vue frontend
        token: result.accessToken,
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
@Post('register2')
  async createUserWithRole(
    @Body() request: createUserRequest,
    @Res() res: Response
  ) {
    try {
      // Validate role
      const validRoles = ['Admin', 'Teacher', 'Head_Department', 'Student'];
      if (request.role && !validRoles.includes(request.role)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role specified",
          validRoles: validRoles
        });
      }

      // Default to Student if no role specified
      if (!request.role) {
        request.role = 'Student';
      }

      const newUser = await this.usersService.create(request);

      return res.json({
        success: true,
        message: "User created successfully",
        user: {
          id: newUser._id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          role: newUser.role,
          department: newUser.department,
          subject: newUser.subject
        }
      });
    } catch (error) {
      return res.status(error.status || 400).json({
        success: false,
        message: error.message || "Failed to create user"
      });
    }
  }

  // --- Enhanced Login with Role Information ---
  // --- Enhanced Login with Role Information ---
@Post('login')
@UseGuards(LocalAuthGuard)
async login(
  @CurrentUser() user: any,
  @Body('returnUrl') returnUrl: string,
  @Res({ passthrough: false }) res: Response,
) {
  try {
    console.log(' SSO Login POST received - START');
    console.log(' User object:', JSON.stringify(user, null, 2));
    console.log(' Return URL:', returnUrl);
    
    if (!user) {
      console.error(' No user object from LocalAuthGuard');
      throw new UnauthorizedException('No user found');
    }

    if (!user._id) {
      console.error(' User object missing _id:', user);
      throw new UnauthorizedException('Invalid user data');
    }

    console.log('Calling authService.login...');
    const result = await this.authService.login(user, res);
    console.log(' authService.login completed');
    
    // Get user role
    console.log(' Getting user role...');
    const userDoc = await this.usersService.findOneById(user._id);
    
    if (!userDoc) {
      console.error('❌ User not found in database for ID:', user._id);
      throw new UnauthorizedException('User not found in database');
    }
    
    const userRole = userDoc?.role || 'Student';
    console.log(' User role:', userRole);

    if (returnUrl) {
      console.log(' Processing returnUrl redirect...');
      // Redirect back to RTC with tokens
      const redirectUrl = new URL(returnUrl);
      redirectUrl.searchParams.set('token', result.accessToken);
      redirectUrl.searchParams.set('accessToken', result.accessToken);
      redirectUrl.searchParams.set('refreshToken', result.refreshToken);
      
      console.log(' Redirecting to:', redirectUrl.toString());
      return res.redirect(redirectUrl.toString());
    } 
    
    // JSON response if no returnUrl
    console.log(' Sending JSON response (no returnUrl)');
    return res.json({
      message: "Login successful",
      success: true,
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        role: userRole,
      },
      roles: [userRole],
      role: userRole,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
    
  } catch (error) {
    console.error('❌ Login failed - FULL ERROR:');
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Error details:', error);
    
    // Redirect back with error
    if (returnUrl) {
      console.log(' Redirecting back with error...');
      const errorUrl = new URL(returnUrl);
      errorUrl.searchParams.set('error', 'Login failed: ' + error.message);
      return res.redirect(errorUrl.toString());
    }
    
    throw new UnauthorizedException('Login failed: ' + error.message);
  }
}

  // --- Get Login Page ---
 // In your auth.controller.ts - Check this method
  @Get('login')
  @Render('login')
  showLoginPage(@Query('returnUrl') returnUrl?: string, @Query('error') error?: string) {
    console.log('🎨 Rendering login page with:', { returnUrl, error });
    
    return { 
      returnUrl: returnUrl || '',
      error: error || ''
    };
  }
  // --- Enhanced User Info with Role ---
 @Get("user-info")
async getUserInfo(@Query('token') token?: string, @Query('user_id') userId?: string) {
  try {
    console.log('🔍 User-info request:', { token: token ? 'provided' : 'none', userId });
    
    let actualUserId = userId;
    
    // If token is provided, extract userId from it
    if (token && !userId) {
      try {
        const payload = this.jwtService.verify(token, {
          secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
        });
        actualUserId = payload.userId;
        console.log('✅ Extracted userId from token:', actualUserId);
      } catch (err) {
        console.error('❌ Failed to verify token:', err.message);
        return { error: "Invalid token" };
      }
    }
    
    if (!actualUserId) {
      console.error('❌ No user_id or token provided');
      return { error: "user_id or token is required" };
    }
    
    const user = await this.usersService.findOneById(actualUserId);
    if (!user) {
      console.error('❌ User not found for ID:', actualUserId);
      return { error: "User not found" };
    }
    
    const userRole = user.role || 'Student';
    console.log('✅ User found:', user.email, 'Role:', userRole);
    
    return {
      id: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
      role: userRole, // ⚠️ IMPORTANT: Include role
      roles: [userRole], // Array format
      profile: {
        department: user.department,
        subject: user.subject,
      }
    };
  } catch (error) {
    console.error('❌ User-info endpoint error:', error.message);
    return { error: "Failed to get user info" };
  }
}
  // --- Role Management Endpoints ---
  @Get("user-roles") 
  getUserRoles(@Req() req: Request) {
    return {
      roles: {
        ADMIN: 'Admin',
        TEACHER: 'Teacher', 
        HEAD_OF_DEPARTMENT: 'Head_Department',
        STUDENT: 'Student'
      },
      permissions: {
        'Admin': [
          'manage_users', 
          'manage_courses', 
          'view_reports', 
          'manage_system',
          'edit_content',
          'delete_content',
          'view_all_data',
          'manage_departments',
          'approve_budgets'
        ],
        'Teacher': [
          'manage_courses', 
          'edit_content', 
          'view_students',
          'grade_assignments',
          'create_assignments'
        ], 
        'Head_Department': [
          'manage_department_courses', 
          'manage_department_teachers',
          'view_department_reports',
          'edit_department_content',
          'approve_department_requests',
          'view_department_data',
          'schedule_classes'
        ],
        'Student': [
          'view_courses', 
          'submit_assignments', 
          'view_grades',
          'view_profile'
        ]
      }
    };
  }
@Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(@CurrentUser() user: User) {
    console.log('Current user:', user);
    return this.usersService.getUsers();
  }

  // Change user role
  @Post('change-role2')
  async changeRole(
    @Body('userId') userId: string,
    @Body('role') role: 'Admin' | 'Teacher' | 'Head_Department' | 'Student',
    @Res() res: Response
  ) {
    try {
      if (!userId) {
        return res.status(400).json({
          success: false,
          message: 'User ID is required'
        });
      }

      if (!role) {
        return res.status(400).json({
          success: false,
          message: 'Role is required'
        });
      }

      const updatedUser = await this.usersService.updateUserRole(userId, role);

      return res.json({
        success: true,
        message: 'Role updated successfully',
        user: {
          id: updatedUser._id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role
        }
      });
    } catch (error) {
      return res.status(error.status || 500).json({
        success: false,
        message: error.message || 'Failed to update role'
      });
    }
  }

  // --- Enhanced Current User Session ---
  @Get("me")
  async getCurrentUser(@Req() req: Request, @Res() res: Response) {
    console.log('🔍 Checking current user session...');
    
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
      
      // Get user details with role
      const user = await this.usersService.findOneById(payload.userId);
      
      if (!user) {
        console.log('❌ User not found for ID:', payload.userId);
        return res.status(401).json({ authenticated: false });
      }
      
      const userRole = user.role || 'Student';
      
      return res.json({
        authenticated: true,
        user: {
          id: user._id.toString(),
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
          role: userRole,
          profile: {
            department: user.department,
            subject: user.subject,
          }
        },
        role: userRole,
        roles: [userRole],
        id: user._id.toString()
      });
      
    } catch (error) {
      console.log('❌ Session check failed:', error.message);
      return res.status(401).json({ authenticated: false });
    }
  }

  // --- Enhanced Fresh Tokens with Role ---
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
      
      // Get user with role
      const user = await this.usersService.findOneById(payload.userId);
      
      if (!user) {
        console.log('❌ User not found for fresh tokens');
        return res.status(401).json({ error: 'User not found' });
      }
      
      // Generate fresh tokens
      const tokens = await this.authService.generateTokens(user);
      const userRole = user.role || 'Student';
      
      return res.json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user_id: user._id.toString(),
        role: userRole,
        user: {
          id: user._id.toString(),
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
          role: userRole,
          profile: {
            department: user.department,
            subject: user.subject,
          }
        }
      });
      
    } catch (error) {
      console.log('❌ Fresh token generation failed:', error.message);
      return res.status(401).json({ error: 'Failed to generate fresh tokens' });
    }
  }

  // --- Vue.js API Login Endpoint ---
  @Post("api-login")
  async apiLogin(@Body() loginDto: LoginDto, @Res() res: Response) {
    try {
      // Validate user
      const user = await this.authService.validateUser(loginDto.email, loginDto.password);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid credentials"
        });
      }

      // Generate tokens
      const tokens = await this.authService.generateTokens(user);
      
      // Get user role
      const userRole = user.role || 'Student';
      
      // Enhanced user data for Vue frontend
      const enhancedUser = {
        id: user._id.toString(),
        email: user.email,
        name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        role: userRole,
        firstName: user.firstName,
        lastName: user.lastName,
        profile: {
          department: user.department,
          subject: user.subject,
        }
      };

      return res.json({
        message: "Login successful",
        success: true,
        user: enhancedUser,
        roles: [userRole], // Array format for compatibility
        role: userRole,
        token: tokens.accessToken,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      });

    } catch (error) {
      return res.status(401).json({
        success: false,
        message: error.message || "Login failed"
      });
    }
  }

  // --- Create Test Users Endpoint ---
  @Post("create-test-users")
  async createTestUsers(@Res() res: Response) {
    try {
      const testUsers = [
        {
          email: 'admin@rtc.edu.kh',
          password: 'admin123',
          firstName: 'System',
          lastName: 'Administrator',
          role: 'Admin' as const
        },
        {
          email: 'teacher@rtc.edu.kh',
          password: 'teacher123',
          firstName: 'John',
          lastName: 'Teacher',
          role: 'Teacher' as const,
          subject: 'Mathematics'
        },
        {
          email: 'hod@rtc.edu.kh',
          password: 'hod123',
          firstName: 'Jane',
          lastName: 'Department Head',
          role: 'Head_Department' as const,
          department: 'Science Department'
        },
        {
          email: 'student@rtc.edu.kh',
          password: 'student123',
          firstName: 'Alice',
          lastName: 'Student',
          role: 'Student' as const
        }
      ];

      const createdUsers: Array<{
        email: string;
        role: string;
        status: string;
        error?: string;
      }> = [];
      
      for (const userData of testUsers) {
        try {
          // Check if user already exists
          const existingUser = await this.usersService.findOneByEmail(userData.email);
          if (!existingUser) {
            const user = await this.authService.register(userData);
            createdUsers.push({
              email: userData.email,
              role: userData.role,
              status: 'created'
            });
          } else {
            createdUsers.push({
              email: userData.email,
              role: userData.role,
              status: 'already exists'
            });
          }
        } catch (error) {
          createdUsers.push({
            email: userData.email,
            role: userData.role,
            status: 'error',
            error: error.message
          });
        }
      }

      return res.json({
        message: "Test users creation completed",
        users: createdUsers
      });

    } catch (error) {
      return res.status(500).json({
        message: "Failed to create test users",
        error: error.message
      });
    }
  }

  // [Keep all your existing methods below - verify-token, token-login, logout, etc.]
  
@Get("verify-token")
async verifyTokenForPHP(
  @Query('token') queryToken: string, 
  @Req() req: Request,
  @Res() res: Response  // Add Response to set CORS headers
) {
  // Set CORS headers explicitly
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  console.log('🔍 Laravel verify-token request received');
  console.log('🔍 Origin:', req.headers.origin);
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).json({ valid: false, message: "Preflight OK" });
  }

  // Extract token from multiple sources
  let token = queryToken;

  // Check Authorization header
  if (!token && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    token = authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : authHeader;
    console.log('🔍 Token from Authorization header');
  }

  if (!token) {
    console.log('❌ No token provided');
    return res.status(401).json({ 
      valid: false, 
      message: "No token provided" 
    });
  }

  try {
    console.log('🔍 Verifying token...');
    
    // Verify JWT
    const payload = this.jwtService.verify(token, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET')
    });
    
    console.log('✅ Token verified, userId:', payload.userId);
    
    // Get user from database
    const user = await this.usersService.findOneById(payload.userId);
    
    if (!user) {
      console.log('❌ User not found');
      return res.status(401).json({ 
        valid: false, 
        message: "User not found" 
      });
    }

    console.log('✅ User found:', user.email, 'Role:', user.role);
    
    // IMPORTANT: Return format matching Laravel expectations
    return res.json({ 
      valid: true,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        role: user.role || 'Student',  // Single role
        roles: [user.role || 'Student'], // Array format
        department: user.department || null,
        subject: user.subject || null
      },
      token: token,  // Return the same token
      accessToken: token
    });
    
  } catch (error) {
    console.log('❌ Token verification failed:', error.message);
    
    let errorMessage = "Token verification failed";
    if (error.name === 'TokenExpiredError') {
      errorMessage = "Token expired";
    } else if (error.name === 'JsonWebTokenError') {
      errorMessage = "Invalid token";
    }
    
    return res.status(401).json({ 
      valid: false, 
      message: errorMessage,
      error: error.message 
    });
  }
}

  @Post("token-login")
  async loginWithToken(@Body() body: TokenLoginDto, @Res() res: Response) {
    const { token, type } = body;
    const result = await this.authService.loginWithToken(token, type, res);
    return res.json(result);
  }

  @Post("refresh")
  @UseGuards(JwtRefreshAuthGuard)
  async refreshToken(@CurrentUser() user: User, @Res() res: Response) {
    const result = await this.authService.refresh(user, res);
    return res.json(result);
  }

  @UseGuards(JwtAuthGuard)
  @Post("logout")
  async logout(
    @Req() req: any, 
    @Res({ passthrough: true }) res: Response,
    @Query('returnUrl') returnUrl?: string
  ) {
    try {
      const token = this.extractTokenFromHeader(req);
      
      if (token) {
        await this.sessionService.invalidateSession(token);
      }
      
      res.clearCookie('Authentication');
      res.clearCookie('Refresh');
      res.clearCookie('sso_token');
      
      if (returnUrl) {
        const cleanUrl = this.removeTokenParams(returnUrl);
        return res.redirect(cleanUrl);
      }
      
      return { 
        success: true,
        message: "Logged out successfully" 
      };
      
    } catch (error) {
      console.error('Logout error:', error);
      
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
      
      const paramsToRemove = [
        'accessToken', 'refreshToken', 'token', 
        'logout', 'error', 'message'
      ];
      
      paramsToRemove.forEach(param => {
        urlObj.searchParams.delete(param);
      });
      
      urlObj.searchParams.set('logout', 'success');
      
      return urlObj.toString();
    } catch (error) {
      return url
        .replace(/[?&]accessToken=[^&]*/g, '')
        .replace(/[?&]refreshToken=[^&]*/g, '')
        .replace(/[?&]token=[^&]*/g, '')
        + '?logout=success';
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (!authHeader) return undefined;
    
    const [type, token] = authHeader.split(" ");
    return type === "Bearer" ? token : undefined;
  }

  private toPlainObject(obj: any): any {
    return JSON.parse(JSON.stringify(obj));
  }
}
