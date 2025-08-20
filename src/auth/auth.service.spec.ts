import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { Response } from 'express';
import { User } from '../users/schema/user.schema';
import { UsersService } from '../users/users.service';
import { TokenPayload } from './token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User, response: Response) {
    const expiresAccessToken = new Date();
    expiresAccessToken.setTime(
      Date.now() + parseInt(this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')),
    );
    const expiresRefreshToken = new Date();
    expiresRefreshToken.setTime(
      Date.now() + parseInt(this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')),
    );

    const tokenPayload: TokenPayload = { userId: user._id.toHexString() };

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')}ms`,
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')}ms`,
    });

    // Save hashed refresh token in DB
    await this.usersService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) } },
    );

    response.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresAccessToken,
      sameSite: 'strict',
    });
    response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresRefreshToken,
      sameSite: 'strict',
    });

    // Optionally return tokens or user info if needed
    return { accessToken };
  }

  async refresh(user: User, response: Response) {
    // user here is validated by JwtRefreshStrategy (payload.userId)
    // Retrieve the full user record (to get stored refresh token hash)
    const dbUser = await this.usersService.getUser({ _id: user._id });

    if (!dbUser?.refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    // Extract the refresh token from cookies in the request — 
    // you'll need to pass the refresh token string to this method or get it from the context 
    // (adjust depending on how you call this method)
    // For example, pass it as an argument or extract in the controller from the request object

    // For demonstration, assume `refreshToken` passed as argument (adjust accordingly)
    // Here, you need to verify the token itself with JWT, then compare with stored hash
    // This should be done in JwtRefreshStrategy and here you just check the hash again
    // Or you can skip hash comparison here if JwtRefreshStrategy already validated

    // Generate new tokens:
    return this.login(dbUser, response);
  }

  async verifyUser(email: string, password: string) {
    const user = await this.usersService.getUser({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const authenticated = await compare(password, user.password);
    if (!authenticated) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }

  async verifyRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      if (!user?.refreshToken) throw new UnauthorizedException('Invalid refresh token');

      const authenticated = await compare(refreshToken, user.refreshToken);
      if (!authenticated) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      return user;
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await compare(password, user.password))) {
      const { password, ...result } = user.toObject();
      return result;
    }
    return null;
  }
}
