import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import type { Model } from "mongoose";
import type { Session } from "../schemas/session.schema";
import * as crypto from "crypto";

@Injectable()
export class SessionService {
  constructor(@InjectModel('Session') private sessionModel: Model<Session>) {}

  generateDeviceId(deviceInfo: any): string {
    const deviceString = `${deviceInfo.userAgent}-${deviceInfo.ip}`;
    return crypto.createHash("sha256").update(deviceString).digest("hex");
  }

  async createSession(userId: string, deviceInfo: any, tokens: any): Promise<Session> {
    const deviceId = this.generateDeviceId(deviceInfo);
    await this.sessionModel.updateMany({ deviceId }, { isActive: false });
    const session = new this.sessionModel({
      userId,
      deviceId,
      deviceInfo,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    return session.save();
  }

  async getSessionByToken(accessToken: string): Promise<Session | null> {
    return this.sessionModel.findOne({
      accessToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });
  }

  async getUserSessions(userId: string): Promise<Session[]> {
    return this.sessionModel
      .find({ userId, isActive: true, expiresAt: { $gt: new Date() } })
      .sort({ lastActivity: -1 });
  }

  async updateActivity(sessionId: string): Promise<void> {
    await this.sessionModel.updateOne({ _id: sessionId }, { lastActivity: new Date() });
  }

  async invalidateSession(accessToken: string): Promise<void> {
    await this.sessionModel.updateOne({ accessToken }, { isActive: false });
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    await this.sessionModel.updateMany({ userId }, { isActive: false });
  }

  async hasActiveSession(deviceId: string): Promise<boolean> {
    const session = await this.sessionModel.findOne({
      deviceId,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });
    return !!session;
  }
}
