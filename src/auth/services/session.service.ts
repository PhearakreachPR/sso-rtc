import { Injectable, Logger } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { Session } from "../schemas/session.schema";
import * as crypto from "crypto";

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(@InjectModel(Session.name) private sessionModel: Model<Session>) {}

  generateDeviceId(deviceInfo: any): string {
    const userAgent = deviceInfo?.userAgent || "unknown";
    const ip = deviceInfo?.ip || "unknown";
    const deviceString = `${userAgent}-${ip}`;
    return crypto.createHash("sha256").update(deviceString).digest("hex");
  }

  async createSession(userId: string, deviceInfo: any, tokens: any): Promise<Session> {
    const deviceId = this.generateDeviceId(deviceInfo);

    // Deactivate previous sessions for same device
    await this.sessionModel.updateMany({ deviceId }, { isActive: false });

    const session = new this.sessionModel({
      userId,
      deviceId,
      deviceInfo,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    const saved = await session.save();
    this.logger.debug(`Created session for user=${userId}, deviceId=${deviceId}`);
    return saved;
  }

  async getSessionByToken(accessToken: string): Promise<Session | null> {
    const session = await this.sessionModel.findOne({
      accessToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      this.logger.warn(`No active session found for token`);
    }
    return session;
  }

  async getUserSessions(userId: string): Promise<Session[]> {
    return this.sessionModel
      .find({ userId, isActive: true, expiresAt: { $gt: new Date() } })
      .sort({ lastActivity: -1 });
  }

  async updateActivity(sessionId: string): Promise<void> {
    await this.sessionModel.updateOne(
      { _id: sessionId },
      { lastActivity: new Date() }
    );
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
