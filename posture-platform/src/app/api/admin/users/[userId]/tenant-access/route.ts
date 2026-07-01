/**
 * Grant/revoke TenantAccess for an existing CUSTOMER_VIEWER User.
 *
 * Gated to TENANT_ACCESS_MANAGEMENT_ROLES (SUPER_ADMIN or ANALYST) — this is
 * routine customer-onboarding work analysts already do elsewhere (see
 * ../route-helpers.ts docstring for the full authorization-split rationale),
 * distinct from the SUPER_ADMIN-only User create/role-change/deactivate
 * actions in ../route.ts and ../[userId]/route.ts.
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { tenantAccessActionSchema } from '../../schemas';
import { requireRoleOrAudit, TENANT_ACCESS_MANAGEMENT_ROLES } from '../../route-helpers';

interface RouteParams {
  params: { userId: string };
}

async function loadTargetUserInOrg(userId: string, organizationId: string) {
  return prisma.user.findFirst({
    where: { id: userId, organizationId },
    select: { id: true, role: true, organizationId: true },
  });
}

export async function POST(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { userId } = params;

  const authz = await requireRoleOrAudit(TENANT_ACCESS_MANAGEMENT_ROLES, {
    action: 'tenant_access.grant.denied',
    targetType: 'User',
    targetId: userId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const targetUser = await loadTargetUserInOrg(userId, session.organizationId);
  if (!targetUser) {
    // Do not leak existence of users outside the caller's organization.
    return NextResponse.json({ error: 'User not found.' }, { status: 404 });
  }

  if (targetUser.role !== 'CUSTOMER_VIEWER') {
    return NextResponse.json(
      { error: 'TenantAccess only applies to CUSTOMER_VIEWER users.' },
      { status: 400 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const parsed = tenantAccessActionSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }
  const { tenantId } = parsed.data;

  // Verify the target Tenant's organizationId matches the target User's
  // organizationId (both must belong to the admin's own org) before creating
  // the row — this is the isolation boundary this endpoint exists to enforce.
  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: targetUser.organizationId },
    select: { id: true },
  });
  if (!tenant) {
    return NextResponse.json(
      { error: 'Tenant not found in your organization.' },
      { status: 404 },
    );
  }

  const grant = await prisma.tenantAccess.upsert({
    where: { userId_tenantId: { userId, tenantId } },
    create: { userId, tenantId },
    update: {},
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_access.grant',
    targetType: 'TenantAccess',
    targetId: grant.id,
    metadata: { userId, tenantId },
  });

  return NextResponse.json({ id: grant.id, userId: grant.userId, tenantId: grant.tenantId }, { status: 201 });
}

export async function DELETE(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { userId } = params;

  const authz = await requireRoleOrAudit(TENANT_ACCESS_MANAGEMENT_ROLES, {
    action: 'tenant_access.revoke.denied',
    targetType: 'User',
    targetId: userId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const targetUser = await loadTargetUserInOrg(userId, session.organizationId);
  if (!targetUser) {
    return NextResponse.json({ error: 'User not found.' }, { status: 404 });
  }

  // tenantId may be provided as a query param (for a simple <form method="POST">
  // style revoke action / fetch DELETE with body) — accept either JSON body or
  // query string for convenience, but validate the same way.
  let tenantId: string | null = request.nextUrl.searchParams.get('tenantId');
  if (!tenantId) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      body = undefined;
    }
    const parsed = tenantAccessActionSchema.safeParse(body);
    if (parsed.success) {
      tenantId = parsed.data.tenantId;
    }
  }

  const parsedTenantId = tenantAccessActionSchema.safeParse({ tenantId });
  if (!parsedTenantId.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsedTenantId.error.flatten() },
      { status: 400 },
    );
  }

  const grant = await prisma.tenantAccess.findFirst({
    where: { userId, tenantId: parsedTenantId.data.tenantId },
  });
  if (!grant) {
    return NextResponse.json({ error: 'Grant not found.' }, { status: 404 });
  }

  await prisma.tenantAccess.delete({ where: { id: grant.id } });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_access.revoke',
    targetType: 'TenantAccess',
    targetId: grant.id,
    metadata: { userId, tenantId: parsedTenantId.data.tenantId },
  });

  return NextResponse.json({ ok: true });
}
