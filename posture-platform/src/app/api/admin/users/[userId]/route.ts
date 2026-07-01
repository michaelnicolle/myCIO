/**
 * Admin user-management: fetch/update a single User (role change, active
 * toggle, deactivate). Gated SUPER_ADMIN-only — see ../route-helpers.ts for
 * the documented authorization split.
 *
 * There is no hard DELETE here: Users are deactivated (isActive = false)
 * rather than removed, so audit history / AuditLog.actorUserId references
 * remain valid (AuditLog.actorUserId is onDelete: SetNull, but we still
 * prefer soft-deactivation so the admin UI can show "who used to have
 * access"). "Delete" in the admin UI means "deactivate".
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { updateUserSchema } from '../schemas';
import { requireRoleOrAudit, USER_MANAGEMENT_ROLES } from '../route-helpers';

interface RouteParams {
  params: { userId: string };
}

export async function GET(_request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { userId } = params;

  const authz = await requireRoleOrAudit(USER_MANAGEMENT_ROLES, {
    action: 'user.view.denied',
    targetType: 'User',
    targetId: userId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const user = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      tenantAccess: {
        select: {
          id: true,
          tenantId: true,
          createdAt: true,
          tenant: { select: { id: true, displayName: true } },
        },
        orderBy: { createdAt: 'desc' },
      },
    },
  });

  if (!user) {
    // Do not leak existence of users outside the caller's organization.
    return NextResponse.json({ error: 'User not found.' }, { status: 404 });
  }

  return NextResponse.json({ user });
}

export async function PATCH(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { userId } = params;

  const authz = await requireRoleOrAudit(USER_MANAGEMENT_ROLES, {
    action: 'user.update.denied',
    targetType: 'User',
    targetId: userId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
  });
  if (!target) {
    return NextResponse.json({ error: 'User not found.' }, { status: 404 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }

  const parsed = updateUserSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input.', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { role, isActive, name } = parsed.data;

  // Footgun prevention: a SUPER_ADMIN must not be able to deactivate (or
  // demote away from SUPER_ADMIN in a way that could lock them out) their own
  // account through this UI.
  if (target.id === session.userId && isActive === false) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.deactivate.self_denied',
      targetType: 'User',
      targetId: userId,
      metadata: { reason: 'cannot_deactivate_self' },
    }).catch(() => {});
    return NextResponse.json(
      { error: 'You cannot deactivate your own account.' },
      { status: 400 },
    );
  }

  const previousRole = target.role;
  const previousIsActive = target.isActive;

  const updated = await prisma.user.update({
    where: { id: userId },
    data: {
      ...(role !== undefined ? { role } : {}),
      ...(isActive !== undefined ? { isActive } : {}),
      ...(name !== undefined ? { name } : {}),
    },
  });

  if (role !== undefined && role !== previousRole) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.role_change',
      targetType: 'User',
      targetId: updated.id,
      metadata: { previousRole, newRole: role },
    });
  }

  if (isActive !== undefined && isActive !== previousIsActive) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: isActive ? 'user.activate' : 'user.deactivate',
      targetType: 'User',
      targetId: updated.id,
      metadata: { previousIsActive },
    });
  }

  return NextResponse.json({
    id: updated.id,
    email: updated.email,
    name: updated.name,
    role: updated.role,
    isActive: updated.isActive,
    updatedAt: updated.updatedAt,
  });
}

/**
 * Deactivates a user (soft-delete). Kept as DELETE for REST conformance with
 * the admin UI's "remove access" action, but never hard-deletes the row —
 * see the module docstring.
 */
export async function DELETE(_request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const { userId } = params;

  const authz = await requireRoleOrAudit(USER_MANAGEMENT_ROLES, {
    action: 'user.deactivate.denied',
    targetType: 'User',
    targetId: userId,
  });
  if ('response' in authz) {
    return authz.response;
  }
  const { session } = authz;

  if (userId === session.userId) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.deactivate.self_denied',
      targetType: 'User',
      targetId: userId,
      metadata: { reason: 'cannot_deactivate_self' },
    }).catch(() => {});
    return NextResponse.json(
      { error: 'You cannot deactivate your own account.' },
      { status: 400 },
    );
  }

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
  });
  if (!target) {
    return NextResponse.json({ error: 'User not found.' }, { status: 404 });
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { isActive: false },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'user.deactivate',
    targetType: 'User',
    targetId: updated.id,
    metadata: { previousIsActive: target.isActive },
  });

  return NextResponse.json({ id: updated.id, isActive: updated.isActive });
}
