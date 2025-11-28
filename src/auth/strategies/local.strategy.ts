// src/auth/strategies/local.strategy.ts - USE THIS VERSION
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ 
      usernameField: 'email', 
      passwordField: "password"
    });
    console.log('🔐 LocalStrategy initialized');
  }

  async validate(email: string, password: string): Promise<any> {
    console.log('🔐 LocalStrategy validate called with:', { email });
    
    try {
      const user = await this.authService.validateUser(email, password);
      
      if (!user) {
        console.log('❌ LocalStrategy: User validation failed');
        throw new UnauthorizedException('Invalid credentials');
      }
      
      console.log('✅ LocalStrategy: User validated successfully', { 
        id: user._id, 
        email: user.email 
      });
      
      return user;
    } catch (error) {
      console.error('❌ LocalStrategy error:', error.message);
      throw new UnauthorizedException(error.message);
    }
  }
}