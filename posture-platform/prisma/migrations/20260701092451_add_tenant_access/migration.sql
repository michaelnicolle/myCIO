-- CreateTable
CREATE TABLE "TenantAccess" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TenantAccess_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TenantAccess_userId_idx" ON "TenantAccess"("userId");

-- CreateIndex
CREATE INDEX "TenantAccess_tenantId_idx" ON "TenantAccess"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "TenantAccess_userId_tenantId_key" ON "TenantAccess"("userId", "tenantId");

-- AddForeignKey
ALTER TABLE "TenantAccess" ADD CONSTRAINT "TenantAccess_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantAccess" ADD CONSTRAINT "TenantAccess_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
