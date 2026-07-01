/**
 * The requireRole() authorization guard used by API route handlers and server
 * components. See src/lib/auth/types.ts for the Role type definition (kept
 * separate to avoid a circular import between this file and ./options, which
 * both need Role).
 */

import { getServerSession } from 'next-auth/next';
import { prisma } from '@/lib/db/client';
import { authOptions } from './options';
import type { Role } from './types';

export type { Role } from './types';
export { isRole } from './types';

export interface AuthorizedSession {
  userId: string;
  email: string;
  role: Role;
  organizationId: string;
}

export class UnauthenticatedError extends Error {
  constructor() {
    super('No authenticated session.');
    this.name = 'UnauthenticatedError';
  }
}

export class ForbiddenError extends Error {
  constructor(public readonly role: Role, public readonly allowedRoles: readonly Role[]) {
    super(`Role ${role} is not permitted; requires one of: ${allowedRoles.join(', ')}.`);
    this.name = 'ForbiddenError';
  }
}

/**
 * Resolves the current server-side session without enforcing a role. Useful
 * when a route needs the actor identity for audit logging even on a denied
 * path (e.g. logging an unauthorized credential-view attempt).
 *
 * Returns `null` if there is no valid session at all.
 */
export async function getAuthorizedSession(): Promise<AuthorizedSession | null> {
  const session = await getServerSession(authOptions);
  if (!session?.user?.id || !session.user.role || !session.user.organizationId) {
    return null;
  }
  return {
    userId: session.user.id,
    email: session.user.email,
    role: session.user.role,
    organizationId: session.user.organizationId,
  };
}

/**
 * Enforces that the current request has an authenticated session whose role is
 * one of `allowedRoles`. Throws `UnauthenticatedError` or `ForbiddenError`
 * (never returns a "falsy" value) so callers cannot accidentally ignore a
 * denial — route handlers should catch these and respond 401/403, and should
 * still call writeAuditLog for the denied attempt where the action is
 * sensitive (e.g. credential access/rotation).
 *
 * Usage in a route handler:
 *   const session = await requireRole(['ANALYST', 'SUPER_ADMIN']);
 */
export async function requireRole(allowedRoles: readonly Role[]): Promise<AuthorizedSession> {
  const session = await getAuthorizedSession();
  if (!session) {
    throw new UnauthenticatedError();
  }
  if (!allowedRoles.includes(session.role)) {
    throw new ForbiddenError(session.role, allowedRoles);
  }
  return session;
}

/**
 * Returns the set of Tenant ids `session` is permitted to see.
 *
 * SUPER_ADMIN/ANALYST are MSP staff and may see every Tenant owned by their
 * Organization — the `'ALL'` sentinel tells callers to scope by
 * `organizationId` alone, as before.
 *
 * CUSTOMER_VIEWER represents a customer's own staff. A single Organization
 * (the MSP) can own many unrelated customers' Tenant rows, so
 * organizationId scoping alone would let one customer's viewer see every
 * other customer's posture data — this is the isolation boundary that
 * matters for that role. Access is granted explicitly via `TenantAccess`
 * rows (see prisma/schema.prisma); a CUSTOMER_VIEWER with no grants sees
 * nothing.
 */
export async function getAccessibleTenantIds(session: AuthorizedSession): Promise<'ALL' | string[]> {
  if (session.role === 'SUPER_ADMIN' || session.role === 'ANALYST') {
    return 'ALL';
  }

  const grants = await prisma.tenantAccess.findMany({
    where: { userId: session.userId },
    select: { tenantId: true },
  });
  return grants.map((g) => g.tenantId);
}

/**
 * Throws ForbiddenError-equivalent behavior by returning `false` if `session`
 * may not view `tenantId`. Callers should treat `false` the same as "not
 * found" (404), never revealing whether the tenant exists to a caller
 * without access.
 */
export async function canAccessTenant(session: AuthorizedSession, tenantId: string): Promise<boolean> {
  const accessible = await getAccessibleTenantIds(session);
  if (accessible === 'ALL') return true;
  return accessible.includes(tenantId);
}
