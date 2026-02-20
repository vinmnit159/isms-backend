-- Add Google Drive OAuth fields to Integration table
ALTER TABLE "Integration" ADD COLUMN IF NOT EXISTS "refreshToken" TEXT;
ALTER TABLE "Integration" ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMP(3);
ALTER TABLE "Integration" ADD COLUMN IF NOT EXISTS "metadata" JSONB;
