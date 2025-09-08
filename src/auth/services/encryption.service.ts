// src/auth/services/encryption.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly secretKey: string;
  private readonly key: Buffer;

  constructor(private configService: ConfigService) {
    this.secretKey = this.configService.getOrThrow('SSO_ENCRYPTION_KEY');
    // Create a proper key from the secret
    this.key = crypto.createHash('sha256').update(this.secretKey).digest();
  }

  encrypt(text: string): { encrypted: string; iv: string; tag: string } {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    cipher.setAAD(Buffer.from('sso-auth', 'utf8'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  decrypt(encryptedData: { encrypted: string; iv: string; tag: string }): string {
    try {
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const tag = Buffer.from(encryptedData.tag, 'hex');
      
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAAD(Buffer.from('sso-auth', 'utf8'));
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Failed to decrypt SSO token');
    }
  }

  encryptToken(payload: any): string {
    const jsonString = JSON.stringify(payload);
    const encrypted = this.encrypt(jsonString);
    
    // Combine all parts into a single string
    return `${encrypted.encrypted}.${encrypted.iv}.${encrypted.tag}`;
  }

  decryptToken(encryptedToken: string): any {
    try {
      const [encrypted, iv, tag] = encryptedToken.split('.');
      
      if (!encrypted || !iv || !tag) {
        throw new Error('Invalid token format');
      }

      const decrypted = this.decrypt({ encrypted, iv, tag });
      return JSON.parse(decrypted);
    } catch (error) {
      throw new Error('Invalid or expired SSO token');
    }
  }
}