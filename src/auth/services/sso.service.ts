// src/auth/services/sso.service.ts
import { Injectable, UnauthorizedException } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import type { Response, Request } from "express"
import { EncryptionService } from "./encryption.service"
import { AuthService } from "../auth.service"
import { UsersService } from "../../users/users.service"
import { hash } from "bcryptjs"

interface SSOTokenPayload {
  userId: string
  email: string
  firstName?: string
  lastName?: string
  roles?: string[]
  exp: number // expiration timestamp
  iat: number // issued at timestamp
  domain: string // originating domain
}

@Injectable()
export class SSOService {
  private readonly SSO_COOKIE_NAME = "sso_session"
  private readonly SSO_COOKIE_DOMAIN = "localhost" // Use 'localhost' for local development
  private readonly SSO_TOKEN_EXPIRY = 24 * 60 * 60 * 1000 // 24 hours

  constructor(
    private readonly encryptionService: EncryptionService,
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {}

  // Create SSO session after successful login
  async createSSOSession(user: any, response: Response, originDomain: string): Promise<void> {
    const payload: SSOTokenPayload = {
      userId: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: user.roles || [],
      exp: Date.now() + this.SSO_TOKEN_EXPIRY,
      iat: Date.now(),
      domain: originDomain,
    }

    const encryptedToken = this.encryptionService.encryptObject(payload)

    const isProd = this.configService.get("NODE_ENV") === "production"

    response.cookie(this.SSO_COOKIE_NAME, encryptedToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      domain: isProd ? this.SSO_COOKIE_DOMAIN : undefined,
      expires: new Date(Date.now() + this.SSO_TOKEN_EXPIRY),
      path: "/",
    })
  }

  // Check if user has valid SSO session
  async checkSSOSession(request: Request): Promise<SSOTokenPayload | null> {
    try {
      const ssoToken = request.cookies?.[this.SSO_COOKIE_NAME]
      if (!ssoToken) return null

      const payload = this.encryptionService.decryptObject(ssoToken) as SSOTokenPayload

      if (payload.exp < Date.now()) return null

      const user = await this.usersService.findOneById(payload.userId)
      if (!user) return null

      const userObj = this.toPlainObject(user)
      if (userObj.isActive === false) return null

      return payload
    } catch (error) {
      console.error("SSO session check failed:", error)
      return null
    }
  }

  // Auto-login user from SSO session
  async autoLoginFromSSO(
    request: Request,
    response: Response,
    returnUrl?: string,
  ): Promise<{ success: boolean; redirectUrl?: string; user?: any; tokens?: any }> {
    try {
      const ssoPayload = await this.checkSSOSession(request)
      if (!ssoPayload) return { success: false }

      const user = await this.usersService.findOneById(ssoPayload.userId)
      if (!user) return { success: false }

      const tokens = await this.authService.generateTokens(user)

      const expiresAccessToken = new Date(
        Date.now() + Number.parseInt(this.configService.getOrThrow("JWT_ACCESS_TOKEN_EXPIRATION_MS")),
      )
      const expiresRefreshToken = new Date(
        Date.now() + Number.parseInt(this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION_MS")),
      )

      const isProd = this.configService.get("NODE_ENV") === "production"

      response.cookie("Authentication", tokens.accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        expires: expiresAccessToken,
      })

      response.cookie("Refresh", tokens.refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
        path: "/auth/refresh",
        expires: expiresRefreshToken,
      })

      const hashedRefreshToken = await hash(tokens.refreshToken, 10)
      await this.usersService.updateUser({ _id: user._id }, { $set: { refreshToken: hashedRefreshToken } })

      let finalRedirectUrl = returnUrl
      if (returnUrl && tokens.accessToken) {
        try {
          const url = new URL(returnUrl)
          url.searchParams.set("access_token", tokens.accessToken)
          url.searchParams.set("user_id", user._id.toString())
          finalRedirectUrl = url.toString()
        } catch (error) {
          console.error("Error creating redirect URL:", error)
          const separator = returnUrl.includes("?") ? "&" : "?"
          finalRedirectUrl = `${returnUrl}${separator}access_token=${tokens.accessToken}&user_id=${user._id.toString()}`
        }
      }

      const sanitizedUser = await this.getSanitizedUser(user._id.toString())

      return { success: true, redirectUrl: finalRedirectUrl, user: sanitizedUser, tokens }
    } catch (error) {
      console.error("Auto-login from SSO failed:", error)
      return { success: false }
    }
  }

  // Clear SSO session
  async clearSSOSession(response: Response): Promise<void> {
    const isProd = this.configService.get("NODE_ENV") === "production"

    response.clearCookie(this.SSO_COOKIE_NAME, {
      domain: isProd ? this.SSO_COOKIE_DOMAIN : undefined,
      path: "/",
    })
  }

  // Validate domain is allowed for SSO
  async validateSSODomain(domain: string): Promise<boolean> {
    const allowedDomains = await this.getAllowedSSODomains()
    return allowedDomains.some((allowed) => domain === allowed || domain.endsWith("." + allowed))
  }

  private async getAllowedSSODomains(): Promise<string[]> {
    return [
      "localhost",
      "localhost:3000",
      "localhost:3001",
      "localhost:3002",
      "localhost:5000",
      "localhost:60000",
      "127.0.0.1",
      "127.0.0.1:5000",
      "127.0.0.1:60000",
    ]
  }

  // Generate SSO login URL
  generateSSOLoginUrl(targetDomain: string, returnUrl?: string): string {
    const ssoBaseUrl = this.configService.get("SSO_SERVER_URL") || "http://localhost:3000"
    const loginUrl = new URL("/auth/sso-check", ssoBaseUrl)

    if (returnUrl) loginUrl.searchParams.set("returnUrl", returnUrl)
    loginUrl.searchParams.set("targetDomain", targetDomain)

    return loginUrl.toString()
  }

  // Refresh SSO session
  async refreshSSOSession(request: Request, response: Response): Promise<boolean> {
    try {
      const ssoPayload = await this.checkSSOSession(request)
      if (!ssoPayload) return false

      const user = await this.usersService.findOneById(ssoPayload.userId)
      if (!user) return false

      await this.createSSOSession(user, response, ssoPayload.domain)
      return true
    } catch (error) {
      console.error("SSO session refresh failed:", error)
      return false
    }
  }

  // Helpers
  private toPlainObject(user: any): any {
    if (!user) return null
    if (typeof user.toObject === "function") return user.toObject()
    if (typeof user.toJSON === "function") return user.toJSON()
    return JSON.parse(JSON.stringify(user))
  }

  private async getSanitizedUser(userId: string): Promise<any> {
    try {
      const user = await this.usersService.findOneById(userId)
      if (!user) throw new UnauthorizedException("User not found")

      const userObject = this.toPlainObject(user)
      const { password, refreshToken, ...sanitizedUser } = userObject
      return sanitizedUser
    } catch {
      throw new UnauthorizedException("Failed to get user data")
    }
  }
}
