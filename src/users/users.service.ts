// src/users/users.service.ts
import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schema/user.schema';
import { FilterQuery, Model, UpdateQuery, Types } from 'mongoose';
import { createUserRequest } from './dto/create-user.request';
import { hash } from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  async create(data: createUserRequest): Promise<UserDocument> {
    const existingUser = await this.userModel.findOne({ 
      email: data.email.toLowerCase().trim() 
    });
    
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await hash(data.password, 12);

    const userData: Partial<User> = {
      email: data.email.toLowerCase().trim(),
      password: hashedPassword,
      isActive: true,
      createdAt: new Date(),
      role: data.role || 'Student', // Add role support
    };

    // Add optional fields if provided
    if (data.firstName) {
      userData.firstName = data.firstName.trim();
    }
    if (data.lastName) {
      userData.lastName = data.lastName.trim();
    }
    if (data.department) {
      userData.department = data.department.trim();
    }
    if (data.subject) {
      userData.subject = data.subject.trim();
    }

    const newUser = new this.userModel(userData);
    return newUser.save();
}
  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ 
      email: email.toLowerCase().trim() 
    }).exec();
  }
async findOneByEmail(email: string): Promise<UserDocument | null> {
  return this.findByEmail(email);
}

  async getUsers(): Promise<UserDocument[]> {
    return this.userModel
      .find()
      .populate({ 
        path: 'roles', 
        populate: { path: 'permissions' } 
      })
      .exec();
  }

  async getUser(query: FilterQuery<User>): Promise<UserDocument | null> {
    try {
      const user = await this.userModel
        .findOne(query)
        .populate({ 
          path: 'roles', 
          populate: { path: 'permissions' } 
        })
        .exec();
      
      return user;
    } catch (error) {
      console.error('Error finding user:', error);
      return null;
    }
  }

  async getUserOrThrow(query: FilterQuery<User>): Promise<UserDocument> {
    const user = await this.getUser(query);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async updateUser(
    query: FilterQuery<User>, 
    data: UpdateQuery<User>
  ): Promise<UserDocument | null> {
    return this.userModel
      .findOneAndUpdate(query, data, { new: true })
      .exec();
  }

  async findOneById(id: string): Promise<UserDocument | null> {
    if (!Types.ObjectId.isValid(id)) {
      return null;
    }
    
    return this.userModel
      .findById(id)
      .populate({ 
        path: 'roles', 
        populate: { path: 'permissions' } 
      })
      .exec();
  }

  async findOneByIdOrThrow(id: string): Promise<UserDocument> {
    const user = await this.findOneById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async updateLastLogin(userId: string): Promise<void> {
    await this.userModel
      .findByIdAndUpdate(userId, { 
        $set: { lastLoginAt: new Date() } 
      })
      .exec();
  }

  async deactivateUser(userId: string): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(
        userId, 
        { $set: { isActive: false } },
        { new: true }
      )
      .exec();
  }

  async activateUser(userId: string): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(
        userId, 
        { $set: { isActive: true } },
        { new: true }
      )
      .exec();
  }

  async deleteUser(userId: string): Promise<boolean> {
    const result = await this.userModel.findByIdAndDelete(userId).exec();
    return !!result;
  }

  async verifyEmail(userId: string): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(
        userId,
        { 
          $set: { 
            isEmailVerified: true,
            emailVerifiedAt: new Date()
          } 
        },
        { new: true }
      )
      .exec();
  }

  async updateProfile(
    userId: string, 
    data: { firstName?: string; lastName?: string }
  ): Promise<UserDocument | null> {
    const updateData: any = {};
    
    if (data.firstName !== undefined) {
      updateData.firstName = data.firstName?.trim() || null;
    }
    if (data.lastName !== undefined) {
      updateData.lastName = data.lastName?.trim() || null;
    }

    return this.userModel
      .findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true }
      )
      .exec();
  }

  async getUserStats(): Promise<{
    total: number;
    active: number;
    inactive: number;
    verified: number;
    unverified: number;
  }> {
    const [
      total,
      active,
      verified
    ] = await Promise.all([
      this.userModel.countDocuments({}),
      this.userModel.countDocuments({ isActive: true }),
      this.userModel.countDocuments({ isEmailVerified: true })
    ]);

    return {
      total,
      active,
      inactive: total - active,
      verified,
      unverified: total - verified
    };
  }

  async searchUsers(searchTerm: string, limit: number = 10): Promise<UserDocument[]> {
    const searchRegex = new RegExp(searchTerm, 'i');
    
    return this.userModel
      .find({
        $or: [
          { email: { $regex: searchRegex } },
          { firstName: { $regex: searchRegex } },
          { lastName: { $regex: searchRegex } }
        ]
      })
      .limit(limit)
      .exec();
  }
  async updateUserRole(userId: string, role: 'Admin' | 'Teacher' | 'Head_Department' | 'Student') {
  const validRoles = ['Admin', 'Teacher', 'Head_Department', 'Student'];

  if (!validRoles.includes(role)) {
    throw new ConflictException(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
  }

  const updatedUser = await this.userModel.findByIdAndUpdate(
    userId,
    { $set: { role } },
    { new: true }
  ).exec();

  if (!updatedUser) {
    throw new NotFoundException('User not found');
  }

  return updatedUser;
}

}
