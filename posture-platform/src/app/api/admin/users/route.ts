/**
 * Admin user-management: list + create portal Users.
 *
 * Gated SUPER_ADMIN-only (USER_MANAGEMENT_ROLES) — see route-helpers.ts for
 * the documented authorization split. Creating a User here only
 * pre-authorizes an email address + role for Entra ID SSO sign-in; there is
 * no password/invite-email flow (see src/lib/auth/options.ts
 * `lookupPortalUser` and the root README "Security model" item 5).
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { createUserSchema } from './schemas';
import { requireRoleOrAudit, USER_MANAGEMENT_ROLES } from './route-helpers';

export async function GET(): Promise<NextResponse> {
  const authz = await requireRoleOrAudit(USER_MANAGEMENT_ROLES, {
    action: 'user.list.denied',
    targetType: 'User',
    targetId: 'list',
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const users = await prisma.user.findMany({
    where: { organizationId: session.organizationId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      _count: { select: { tenantAccess: true } },
    },
  });

  return NextResponse.json({ users });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const authz = await requireRoleOrAudit(USER_MANAGEMENT_ROLES, {
    action: 'user.create.denied',
    targetType: 'User',
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

  const parsed = createUserSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { email, name, role, tenantIds } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json(
      { error: 'A user with this email already exists.' },
      { status: 409 },
    );
  }

  // Only CUSTOMER_VIEWER uses TenantAccess; ignore any tenantIds supplied for
  // other roles rather than silently granting access that's meaningless for
  // SUPER_ADMIN/ANALYST (who see every Tenant in their Organization by role
  // alone — see src/lib/auth/rbac.ts getAccessibleTenantIds).
  const grantTenantIds = role === 'CUSTOMER_VIEWER' ? tenantIds ?? [] : [];

  if (grantTenantIds.length > 0) {
    // Verify every requested tenant belongs to the admin's own organization
    // BEFORE creating anything — a SUPER_ADMIN at one MSP organization must
    // never be able to grant access to a Tenant belonging to a different
    // Organization.
    const validTenants = await prisma.tenant.findMany({
      where: { id: { in: grantTenantIds }, organizationId: session.organizationId },
      select: { id: true },
    });
    if (validTenants.length !== grantTenantIds.length) {
      return NextResponse.json(
        { error: 'One or more selected tenants were not found in your organization.' },
        { status: 400 },
      );
    }
  }

  const user = await prisma.$transaction(async (tx) => {
    const created = await tx.user.create({
      data: {
        organizationId: session.organizationId,
        email,
        name: name ?? null,
        role,
        isActive: true,
      },
    });

    if (grantTenantIds.length > 0) {
      await tx.tenantAccess.createMany({
        data: grantTenantIds.map((tenantId) => ({ userId: created.id, tenantId })),
      });
    }

    return created;
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'user.create',
    targetType: 'User',
    targetId: user.id,
    metadata: { email: user.email, role: user.role, grantedTenantIds: grantTenantIds },
  });

  return NextResponse.json(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      isActive: user.isActive,
      createdAt: user.createdAt,
    },
    { status: 201 },
  );
}
