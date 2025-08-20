// src/permissions/schema/permission.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema()
export class Permission {
  @Prop({ required: true, unique: true })
  name: string;
}

export const PermissionSchema = SchemaFactory.createForClass(Permission);
