import crypto from 'crypto';
import { env } from '../config/env';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

function getKey(): Buffer {
  // ENCRYPTION_KEY must be a 64-char hex string (32 bytes)
  const key = env.ENCRYPTION_KEY;
  if (key.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(key, 'hex');
}

export function encrypt(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  // Format: iv:encrypted — both as hex
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decrypt(ciphertext: string): string {
  const [ivHex, encryptedHex] = ciphertext.split(':');
  if (!ivHex || !encryptedHex) throw new Error('Invalid ciphertext format');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}
