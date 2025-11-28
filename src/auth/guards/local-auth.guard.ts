// src/auth/guards/local-auth.guard.ts
import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    console.log('🔐 LocalAuthGuard activated');
    
    const request = context.switchToHttp().getRequest();
    console.log('📨 Request body:', request.body);
    
    try {
      const result = await super.canActivate(context);
      console.log('✅ LocalAuthGuard result:', result);
      
      if (result) {
        console.log('👤 User set by guard:', request.user);
      }
      
      return result as boolean;
    } catch (error) {
      console.error('❌ LocalAuthGuard error:', error);
      console.error('Error details:', error.message);
      throw error;
    }
  }

  handleRequest(err: any, user: any, info: any) {
    console.log('🔐 LocalAuthGuard handleRequest called');
    console.log('Error:', err);
    console.log('User:', user);
    console.log('Info:', info);
    
    if (err || !user) {
      console.error('❌ LocalAuthGuard: Authentication failed');
      throw err || new UnauthorizedException('Authentication failed');
    }
    
    console.log('✅ LocalAuthGuard: Authentication successful');
    return user;
  }
}