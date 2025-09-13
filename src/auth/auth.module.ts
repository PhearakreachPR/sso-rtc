import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from '../users/users.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { SessionService } from './services/session.service';
import { SessionSchema } from './schemas/session.schema';
import { DeviceTrackingMiddleware } from './middleware/device-tracking.middleware';
import { EncryptionService } from './services/encryption.service';
import { SSOService } from './services/sso.service';


@Module({
  imports: [
    UsersModule,
    PassportModule,
    ConfigModule,
    MongooseModule.forFeature([{ name: 'Session', schema: SessionSchema }]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_ACCESS_TOKEN_SECRET'),
        signOptions: { 
          expiresIn: configService.get('JWT_ACCESS_TOKEN_EXPIRATION', '15m') // Fixed: provide default value
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController ],
  providers: [
    AuthService,
    LocalStrategy,
    JwtStrategy,
    JwtRefreshStrategy,
    SessionService,
    EncryptionService,
    SSOService, // This should work now
  ],
  exports: [
    AuthService, 
    SessionService,
    SSOService, // Also export SSOService if other modules need it
    JwtModule, 
    EncryptionService,// Export JwtModule if needed
  ],
})
export class AuthModule implements NestModule {
   constructor(private configService: ConfigService) {
    console.log('JWT Access Secret:', this.configService.get('JWT_ACCESS_TOKEN_SECRET'));
    console.log('JWT Access Expiry:', this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_MS'));
    console.log('JWT Refresh Secret:', this.configService.get('JWT_REFRESH_TOKEN_SECRET'));
  }
  
  configure(consumer: MiddlewareConsumer)
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(DeviceTrackingMiddleware)
      .forRoutes(
        { path: 'auth/login', method: RequestMethod.POST },
        { path: 'auth/device-status', method: RequestMethod.GET },
        { path: 'auth/token-login', method: RequestMethod.POST }
      );
  }
}