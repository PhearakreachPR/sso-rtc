// src/auth/services/encryption.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class EncryptionService {
  private readonly algorithm = "aes-256-gcm"
  private readonly secretKey: string
  private readonly key: Buffer

  constructor() {
    this.secretKey = "your-super-secret-key-32-chars-long"
    // Create a proper key from the secret
    this.key = crypto.scryptSync(this.secretKey, "salt", 32)
  }

  // Encrypt any string (for JWT tokens)
  encryptString(text: string): string {
    try {
      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv)

      let encrypted = cipher.update(text, "utf8", "hex")
      encrypted += cipher.final("hex")

      const tag = cipher.getAuthTag()

      // Combine all parts into a single string
      return `${encrypted}.${iv.toString("hex")}.${tag.toString("hex")}`
    } catch (error) {
      console.error("Encryption failed:", error)
      throw new Error("Failed to encrypt token")
    }
  }

  // Decrypt any string (for JWT tokens)
  decryptString(encryptedToken: string): string {
    try {
      // Handle both encrypted and plain tokens for backward compatibility
      if (!encryptedToken.includes(".")) {
        console.log("Plain token detected, returning as-is")
        return encryptedToken
      }

      const parts = encryptedToken.split(".")
      if (parts.length !== 3) {
        console.log("Invalid token format, treating as plain token")
        return encryptedToken
      }

      const [encrypted, ivHex, tagHex] = parts

      if (!encrypted || !ivHex || !tagHex) {
        throw new Error("Invalid token format: missing parts")
      }

      const iv = Buffer.from(ivHex, "hex")
      const tag = Buffer.from(tagHex, "hex")

      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv)
      decipher.setAuthTag(tag)

      let decrypted = decipher.update(encrypted, "hex", "utf8")
      decrypted += decipher.final("utf8")

      return decrypted
    } catch (error) {
      console.error("Decryption failed:", error.message)
      // Return original token if decryption fails (for plain tokens)
      return encryptedToken
    }
  }

  // Encrypt objects (for complex payloads)
  encryptObject(payload: any): string {
    const jsonString = JSON.stringify(payload)
    return this.encryptString(jsonString)
  }

  // Decrypt objects (for complex payloads)
  decryptObject(encryptedToken: string): any {
    try {
      const decryptedString = this.decryptString(encryptedToken)
      return JSON.parse(decryptedString)
    } catch (error) {
      console.error("Object decryption failed:", error.message)
      throw new Error("Failed to decrypt SSO object: " + error.message)
    }
  }
}

// Create singleton instance
export const encryptionService = new EncryptionService()
