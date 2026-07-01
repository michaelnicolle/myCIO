/**
 * Role definitions and the requireRole() authorization guard used by API route
 * handlers and server components. Mirrors the Prisma `UserRole` enum
 * (SUPER_ADMIN / ANALYST / CUSTOMER_VIEWER) — kept as a local literal union
 * (rather than importing the Prisma enum type) so this module has no hard
 * dependency on Prisma client generation having run yet.
 */

import { getServerSession } from 'next-auth/next';
import { authOptions } from './options';

export type Role = 'SUPER_ADMIN' | 'ANALYST' | 'CUSTOMER_VIEWER';

const ALL_ROLES: readonly Role[] = ['SUPER_ADMIN', 'ANALYST', 'CUSTOMER_VIEWER'];

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ALL_ROLES as readonly string[]).includes(value);
}

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
