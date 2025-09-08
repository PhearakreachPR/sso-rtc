// src/interfaces/device-info.interface.ts
export interface DeviceInfo {
  userAgent?: string;
  platform?: string;
  browser?: string;
  version?: string;
  deviceType?: 'mobile' | 'tablet' | 'desktop';
  os?: string;
  ipAddress?: string;
  deviceId?: string;
  appName?: string;
  timestamp?: Date;
}