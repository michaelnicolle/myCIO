-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('SUPER_ADMIN', 'ANALYST', 'CUSTOMER_VIEWER');

-- CreateEnum
CREATE TYPE "TenantStatus" AS ENUM ('ONBOARDING', 'ACTIVE', 'CREDENTIAL_EXPIRED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "CredentialType" AS ENUM ('CLIENT_SECRET', 'CERTIFICATE');

-- CreateEnum
CREATE TYPE "NistFunction" AS ENUM ('GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL');

-- CreateEnum
CREATE TYPE "Framework" AS ENUM ('NIST_CSF_2_0', 'NIST_800_53_R5', 'CIS_M365_V3');

-- CreateEnum
CREATE TYPE "ControlStatus" AS ENUM ('PASS', 'FAIL', 'PARTIAL', 'NOT_APPLICABLE', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'RISK_ACCEPTED');

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "role" "UserRole" NOT NULL DEFAULT 'CUSTOMER_VIEWER',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "entraTenantId" TEXT NOT NULL,
    "status" "TenantStatus" NOT NULL DEFAULT 'ONBOARDING',
    "onboardedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TenantCredential" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "credentialType" "CredentialType" NOT NULL,
    "clientId" TEXT NOT NULL,
    "kmsProvider" TEXT NOT NULL,
    "kmsKeyId" TEXT NOT NULL,
    "kmsKeyVersion" TEXT NOT NULL,
    "wrappedDataKey" BYTEA NOT NULL,
    "encryptionAlgorithm" TEXT NOT NULL DEFAULT 'AES-256-GCM',
    "ciphertext" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "authTag" BYTEA NOT NULL,
    "certificateThumbprint" TEXT,
    "expiresAt" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "TenantCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlDefinition" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "nistFunction" "NistFunction" NOT NULL,
    "severity" "Severity" NOT NULL,
    "requiredSignals" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ControlDefinition_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlMapping" (
    "id" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "framework" "Framework" NOT NULL,
    "frameworkControlId" TEXT NOT NULL,

    CONSTRAINT "ControlMapping_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ControlResult" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "status" "ControlStatus" NOT NULL,
    "evaluatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "detail" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ControlResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "firstDetectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PostureSnapshot" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "takenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "overallScore" INTEGER NOT NULL,
    "functionScores" JSONB NOT NULL,
    "secureScoreCurrent" INTEGER,
    "secureScoreMax" INTEGER,
    "openFindingsBySeverity" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PostureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "actorUserId" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Organization_name_idx" ON "Organization"("name");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_organizationId_idx" ON "User"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_entraTenantId_key" ON "Tenant"("entraTenantId");

-- CreateIndex
CREATE INDEX "Tenant_organizationId_idx" ON "Tenant"("organizationId");

-- CreateIndex
CREATE INDEX "Tenant_status_idx" ON "Tenant"("status");

-- CreateIndex
CREATE INDEX "TenantCredential_tenantId_idx" ON "TenantCredential"("tenantId");

-- CreateIndex
CREATE INDEX "TenantCredential_tenantId_isActive_idx" ON "TenantCredential"("tenantId", "isActive");

-- CreateIndex
CREATE INDEX "ControlDefinition_nistFunction_idx" ON "ControlDefinition"("nistFunction");

-- CreateIndex
CREATE INDEX "ControlMapping_controlId_idx" ON "ControlMapping"("controlId");

-- CreateIndex
CREATE INDEX "ControlMapping_framework_frameworkControlId_idx" ON "ControlMapping"("framework", "frameworkControlId");

-- CreateIndex
CREATE UNIQUE INDEX "ControlMapping_controlId_framework_frameworkControlId_key" ON "ControlMapping"("controlId", "framework", "frameworkControlId");

-- CreateIndex
CREATE INDEX "ControlResult_tenantId_evaluatedAt_idx" ON "ControlResult"("tenantId", "evaluatedAt");

-- CreateIndex
CREATE INDEX "ControlResult_tenantId_controlId_idx" ON "ControlResult"("tenantId", "controlId");

-- CreateIndex
CREATE INDEX "ControlResult_tenantId_status_idx" ON "ControlResult"("tenantId", "status");

-- CreateIndex
CREATE INDEX "Finding_tenantId_status_idx" ON "Finding"("tenantId", "status");

-- CreateIndex
CREATE INDEX "Finding_tenantId_controlId_idx" ON "Finding"("tenantId", "controlId");

-- CreateIndex
CREATE INDEX "Finding_tenantId_severity_idx" ON "Finding"("tenantId", "severity");

-- CreateIndex
CREATE INDEX "PostureSnapshot_tenantId_takenAt_idx" ON "PostureSnapshot"("tenantId", "takenAt");

-- CreateIndex
CREATE INDEX "AuditLog_organizationId_createdAt_idx" ON "AuditLog"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_targetType_targetId_idx" ON "AuditLog"("targetType", "targetId");

-- CreateIndex
CREATE INDEX "AuditLog_actorUserId_idx" ON "AuditLog"("actorUserId");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Tenant" ADD CONSTRAINT "Tenant_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantCredential" ADD CONSTRAINT "TenantCredential_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ControlMapping" ADD CONSTRAINT "ControlMapping_controlId_fkey" FOREIGN KEY ("controlId") REFERENCES "ControlDefinition"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_controlId_fkey" FOREIGN KEY ("controlId") REFERENCES "ControlDefinition"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PostureSnapshot" ADD CONSTRAINT "PostureSnapshot_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
