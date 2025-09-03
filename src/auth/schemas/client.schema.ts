// src/auth/schemas/client.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Client extends Document {
  @Prop({ required: true, unique: true })
  clientId: string;

  @Prop()
  clientSecret?: string; // present for confidential clients

  @Prop({ type: [String], default: [] })
  redirectUris: string[];

  @Prop({ default: false })
  confidential: boolean; // true if client must use client_secret

  @Prop()
  name?: string;
}

export const ClientSchema = SchemaFactory.createForClass(Client);
