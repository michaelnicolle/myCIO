/**
 * Tenant creation endpoint. Gated to ANALYST/SUPER_ADMIN — see
 * README.md "Security model" and src/lib/auth/rbac.ts.
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { createTenantSchema } from './schemas';
import { requireTenantManagementRoleOrAudit } from './route-helpers';

export async function POST(request: NextRequest): Promise<NextResponse> {
  const authz = await requireTenantManagementRoleOrAudit({
    action: 'tenant.create.denied',
    targetType: 'Tenant',
    targetId: 'unknown',
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const parsed = createTenantSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { displayName, entraTenantId } = parsed.data;

  const existing = await prisma.tenant.findUnique({ where: { entraTenantId } });
  if (existing) {
    return NextResponse.json(
      { error: 'A tenant with this Entra tenant ID already exists.' },
      { status: 409 },
    );
  }

  const tenant = await prisma.tenant.create({
    data: {
      organizationId: session.organizationId,
      displayName,
      entraTenantId,
      status: 'ONBOARDING',
    },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant.create',
    targetType: 'Tenant',
    targetId: tenant.id,
    metadata: { displayName: tenant.displayName, entraTenantId: tenant.entraTenantId },
  });

  return NextResponse.json(
    {
      id: tenant.id,
      displayName: tenant.displayName,
      entraTenantId: tenant.entraTenantId,
      status: tenant.status,
      onboardedAt: tenant.onboardedAt,
    },
    { status: 201 },
  );
}

export async function GET(): Promise<NextResponse> {
  const authz = await requireTenantManagementRoleOrAudit({
    action: 'tenant.list.denied',
    targetType: 'Tenant',
    targetId: 'list',
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const tenants = await prisma.tenant.findMany({
    where: { organizationId: session.organizationId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      displayName: true,
      entraTenantId: true,
      status: true,
      onboardedAt: true,
    },
  });

  return NextResponse.json({ tenants });
}
