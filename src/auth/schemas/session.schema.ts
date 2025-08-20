import { Schema, type Document } from "mongoose"

export interface Session extends Document {
  userId: string
  deviceId: string
  deviceInfo: {
    userAgent: string
    ip: string
    browser: string
    os: string
    device: string
  }
  accessToken: string
  refreshToken: string
  isActive: boolean
  lastActivity: Date
  createdAt: Date
  expiresAt: Date
}

export const SessionSchema = new Schema({
  userId: { type: String, required: true, index: true },
  deviceId: { type: String, required: true, unique: true },
  deviceInfo: {
    userAgent: { type: String, required: true },
    ip: { type: String, required: true },
    browser: { type: String },
    os: { type: String },
    device: { type: String },
  },
  accessToken: { type: String, required: true },
  refreshToken: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  lastActivity: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
})

// Index for cleanup of expired sessions
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })
