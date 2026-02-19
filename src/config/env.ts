import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  HOST: z.string().default('0.0.0.0'),
  
  // Database
  DATABASE_URL: z.string(),
  
  // JWT
  JWT_SECRET: z.string(),
  JWT_EXPIRES_IN: z.string().default('7d'),
  
  // CORS
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  
  // Logging
  LOG_LEVEL: z.string().default('info'),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string().default(''),
  GOOGLE_CLIENT_SECRET: z.string().default(''),
  // Where Google sends the user after consent — must match Google Console
  GOOGLE_CALLBACK_URL: z.string().default('https://ismsbackend.bitcoingames1346.com/auth/google/callback'),
  // Where backend redirects after successful auth (frontend)
  FRONTEND_URL: z.string().default('https://isms.bitcoingames1346.com'),

  // GitHub OAuth
  GITHUB_CLIENT_ID: z.string().default(''),
  GITHUB_CLIENT_SECRET: z.string().default(''),
  GITHUB_CALLBACK_URL: z.string().default('https://ismsbackend.bitcoingames1346.com/integrations/github/callback'),

  // Encryption (AES-256) — 32 hex bytes = 64 hex chars
  ENCRYPTION_KEY: z.string().default('0000000000000000000000000000000000000000000000000000000000000000'),

  // File uploads — local disk storage
  UPLOAD_DIR: z.string().default('./uploads'),
  // Max file size in bytes (default 50 MB)
  MAX_FILE_SIZE: z.string().transform(Number).default('52428800'),
});

export const env = envSchema.parse(process.env);