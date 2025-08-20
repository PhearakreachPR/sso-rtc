import { Injectable, type NestMiddleware } from "@nestjs/common"
import type { Request, Response, NextFunction } from "express"

@Injectable()
export class DeviceTrackingMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const deviceInfo = {
      userAgent: req.headers["user-agent"] || "",
      ip: req.ip || req.connection.remoteAddress || "",
      browser: this.getBrowser(req.headers["user-agent"] || ""),
      os: this.getOS(req.headers["user-agent"] || ""),
      device: this.getDevice(req.headers["user-agent"] || ""),
    }

    // Attach device info to request
    ;(req as any).deviceInfo = deviceInfo
    next()
  }

  private getBrowser(userAgent: string): string {
    if (userAgent.includes("Chrome")) return "Chrome"
    if (userAgent.includes("Firefox")) return "Firefox"
    if (userAgent.includes("Safari")) return "Safari"
    if (userAgent.includes("Edge")) return "Edge"
    return "Unknown"
  }

  private getOS(userAgent: string): string {
    if (userAgent.includes("Windows")) return "Windows"
    if (userAgent.includes("Mac")) return "macOS"
    if (userAgent.includes("Linux")) return "Linux"
    if (userAgent.includes("Android")) return "Android"
    if (userAgent.includes("iOS")) return "iOS"
    return "Unknown"
  }

  private getDevice(userAgent: string): string {
    if (userAgent.includes("Mobile")) return "Mobile"
    if (userAgent.includes("Tablet")) return "Tablet"
    return "Desktop"
  }
}
