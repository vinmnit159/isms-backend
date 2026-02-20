-- CreateEnum
CREATE TYPE "ComplianceStatus" AS ENUM ('COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AssetType" ADD VALUE 'REPOSITORY';
ALTER TYPE "AssetType" ADD VALUE 'VENDOR';

-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "hostname" TEXT,
ADD COLUMN     "osType" TEXT,
ADD COLUMN     "osVersion" TEXT,
ADD COLUMN     "serialNumber" TEXT,
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'ACTIVE';

-- CreateTable
CREATE TABLE "DeviceCompliance" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "diskEncryptionEnabled" BOOLEAN NOT NULL DEFAULT false,
    "screenLockEnabled" BOOLEAN NOT NULL DEFAULT false,
    "firewallEnabled" BOOLEAN NOT NULL DEFAULT false,
    "antivirusEnabled" BOOLEAN NOT NULL DEFAULT false,
    "systemIntegrityEnabled" BOOLEAN NOT NULL DEFAULT false,
    "autoUpdateEnabled" BOOLEAN NOT NULL DEFAULT false,
    "gatekeeperEnabled" BOOLEAN NOT NULL DEFAULT false,
    "complianceStatus" "ComplianceStatus" NOT NULL DEFAULT 'UNKNOWN',
    "lastCheckedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeviceCompliance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceCheckin" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "payloadJson" JSONB NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeviceCheckin_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeviceEnrollment" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "apiKeyHash" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "enrolledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "DeviceEnrollment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EnrollmentToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "label" TEXT,
    "usedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EnrollmentToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DeviceCompliance_assetId_key" ON "DeviceCompliance"("assetId");

-- CreateIndex
CREATE INDEX "DeviceCheckin_assetId_receivedAt_idx" ON "DeviceCheckin"("assetId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceEnrollment_assetId_key" ON "DeviceEnrollment"("assetId");

-- CreateIndex
CREATE INDEX "DeviceEnrollment_organizationId_idx" ON "DeviceEnrollment"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "EnrollmentToken_token_key" ON "EnrollmentToken"("token");

-- CreateIndex
CREATE INDEX "EnrollmentToken_organizationId_idx" ON "EnrollmentToken"("organizationId");

-- AddForeignKey
ALTER TABLE "DeviceCompliance" ADD CONSTRAINT "DeviceCompliance_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceCheckin" ADD CONSTRAINT "DeviceCheckin_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceEnrollment" ADD CONSTRAINT "DeviceEnrollment_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;
