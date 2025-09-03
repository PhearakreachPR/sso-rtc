export interface DeviceInfo {
  userAgent: string;
  ip: string;
  browser: string;
  os: string;
  device: string;
  platform?: string; // Optional: add if you want more detailed platform info
}