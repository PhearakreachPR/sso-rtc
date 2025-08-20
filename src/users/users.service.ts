// src/users/users.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { FilterQuery, Model, UpdateQuery, Types } from 'mongoose';
import { createUserRequest } from './dto/create-user.request';
import { hash } from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async create(data: createUserRequest) {
    await new this.userModel({
      ...data,
      password: await hash(data.password, 10),
    }).save();
  }

  async getUsers(): Promise<User[]> {
    return this.userModel
      .find()
      .populate({
        path: 'roles',
        populate: { path: 'permissions' },
      })
      .exec();
  }

  async getUser(query: FilterQuery<User>) {
    const user = await this.userModel
      .findOne(query)
      .populate({
        path: 'roles',
        populate: { path: 'permissions' },
      })
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findByEmail(email: string) {
    return this.userModel.findOne({ email }).exec();
  }

  async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
    return this.userModel.findOneAndUpdate(query, data);
  }

  // ------------------- New method -------------------
  async findOneById(id: string) {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException('User not found');
    }
    return this.userModel.findById(id).populate({
      path: 'roles',
      populate: { path: 'permissions' },
    }).exec();
  }
}
