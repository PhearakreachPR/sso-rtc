// seed.ts
import mongoose, { model } from 'mongoose';
import bcrypt from 'bcryptjs';
import { Permission, PermissionSchema } from './permissions/schema/permission.schema';
import { Role, RoleSchema } from './roles/schema/role.schema';
import { User, UserSchema } from './users/schema/user.schema';

async function seed() {
  try {
    // 1. Connect to MongoDB
    await mongoose.connect('mongodb://127.0.0.1:27017/sso-backend');
    console.log('✅ Connected to MongoDB');

    // 2. Create Mongoose models from your schema classes
    const PermissionModel = model<Permission>('Permission', PermissionSchema);
    const RoleModel = model<Role>('Role', RoleSchema);
    const UserModel = model<User>('User', UserSchema);

    // 3. Clear old data
    await PermissionModel.deleteMany({});
    await RoleModel.deleteMany({});
    await UserModel.deleteMany({});
    console.log('🗑 Old data cleared');

    // 4. Create permissions
    const permissions = await PermissionModel.insertMany([
      { name: 'read' },
      { name: 'write' },
      { name: 'delete' },
      { name: 'manage-users' },
    ]);
    console.log('✅ Permissions seeded');

    // 5. Create roles with permissions
    const adminRole = await RoleModel.create({
      name: 'admin',
      permissions: permissions.map((p) => p._id), // all permissions
    });

    const teacherRole = await RoleModel.create({
      name: 'teacher',
      permissions: [permissions[0]._id, permissions[1]._id], // read + write
    });

    const studentRole = await RoleModel.create({
      name: 'student',
      permissions: [permissions[0]._id], // only read
    });

    const managerRole = await RoleModel.create({
      name: 'manager',
      permissions: [permissions[0]._id, permissions[1]._id, permissions[3]._id], // read + write + manage-users
    });

    console.log('✅ Roles seeded');

    // 6. Create static users with hashed passwords
    const defaultPassword = await bcrypt.hash('password123', 10);

    const users = [
      { name: 'Alice Johnson', email: 'alice.johnson@example.com', roles: [adminRole._id] },
      { name: 'Bob Smith', email: 'bob.smith@example.com', roles: [adminRole._id] },
      { name: 'Charlie Brown', email: 'charlie.brown@example.com', roles: [managerRole._id] },
      { name: 'Diana Prince', email: 'diana.prince@example.com', roles: [managerRole._id] },
      { name: 'Ethan Hunt', email: 'ethan.hunt@example.com', roles: [teacherRole._id] },
      { name: 'Fiona Green', email: 'fiona.green@example.com', roles: [teacherRole._id] },
      { name: 'George Miller', email: 'george.miller@example.com', roles: [teacherRole._id] },
      { name: 'Hannah Lee', email: 'hannah.lee@example.com', roles: [teacherRole._id] },
      { name: 'Ivan KO', email: 'ivan.petrov@example.com', roles: [studentRole._id] },
      { name: 'Julia Roberts', email: 'julia.roberts@example.com', roles: [studentRole._id] },
      { name: 'Kevin Nguyen', email: 'kevin.nguyen@example.com', roles: [studentRole._id] },
      { name: 'Laura Wilson', email: 'laura.wilson@example.com', roles: [studentRole._id] },
      { name: 'Michael Chen', email: 'michael.chen@example.com', roles: [studentRole._id] },
      { name: 'Nina Lopez', email: 'nina.lopez@example.com', roles: [studentRole._id] },
      { name: 'Oscar Martinez', email: 'oscar.martinez@example.com', roles: [studentRole._id] },
      { name: 'Paula Adams', email: 'paula.adams@example.com', roles: [studentRole._id] },
      { name: 'Quinn Taylor', email: 'quinn.taylor@example.com', roles: [studentRole._id] },
      { name: 'Ryan Davis', email: 'ryan.davis@example.com', roles: [studentRole._id] },
      { name: 'Sophia King', email: 'sophia.king@example.com', roles: [studentRole._id] },
      { name: 'Thomas White', email: 'thomas.white@example.com', roles: [studentRole._id] },
    ];

    await UserModel.insertMany(
      users.map((u) => ({
        email: u.email,
        password: defaultPassword,
        name: u.name,
        roles: u.roles,
      })),
    );

    console.log('✅ 20 Users seeded');

    // 7. Disconnect
    await mongoose.disconnect();
    console.log('🚀 Seeding completed successfully!');
  } catch (err) {
    console.error('❌ Seeding failed', err);
    process.exit(1);
  }
}

seed();
