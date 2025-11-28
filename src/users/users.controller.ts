// src/users/users.controller.ts
import { Body, Controller, Get, Post, UseGuards ,Res} from '@nestjs/common';
import { createUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';
import type { Response } from 'express';
import { CurrentUser } from '../auth/current-user.decorator';
import { User } from './schema/user.schema';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  @Post()
  async createUser(@Body() request: createUserRequest) {
    await this.usersService.create(request);
  }
  @Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(@CurrentUser() user: User) {
    console.log('Current user:', user);
    return this.usersService.getUsers();
  }
   @Post('change-role')
  async changeRole(
    @Body('userId') userId: string,
    @Body('role') role: 'Admin' | 'Teacher' | 'Head_Department' | 'Student',
    @Res() res: Response
  ) {
    try {
      const updatedUser = await this.usersService.updateUserRole(userId, role);

      return res.json({
        message: 'Role updated successfully',
        user: {
          id: updatedUser._id,
          email: updatedUser.email,
          role: updatedUser.role
        }
      });
    } catch (error) {
      return res.status(error.status || 500).json({
        message: error.message || 'Failed to update role'
      });
    }
  }
}
