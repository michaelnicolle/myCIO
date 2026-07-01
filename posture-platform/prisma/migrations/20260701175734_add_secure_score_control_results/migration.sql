-- CreateTable
CREATE TABLE "SecureScoreControlResult" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "controlName" TEXT NOT NULL,
    "controlCategory" TEXT NOT NULL,
    "score" DOUBLE PRECISION NOT NULL,
    "evaluatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecureScoreControlResult_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SecureScoreControlResult_tenantId_controlName_evaluatedAt_idx" ON "SecureScoreControlResult"("tenantId", "controlName", "evaluatedAt");

-- CreateIndex
CREATE INDEX "SecureScoreControlResult_tenantId_evaluatedAt_idx" ON "SecureScoreControlResult"("tenantId", "evaluatedAt");

-- AddForeignKey
ALTER TABLE "SecureScoreControlResult" ADD CONSTRAINT "SecureScoreControlResult_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
