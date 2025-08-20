// src/users/users.controller.ts
import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { createUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';

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
}
