/**
 * Shared helpers for the admin user-management API routes: consistent
 * authorization + audit-on-denial handling so every handler in this directory
 * follows the same pattern as src/app/api/tenants/route-helpers.ts (see
 * README.md "Security model" items 5 and 7).
 *
 * Authorization split (documented per task instructions):
 *   - Creating a User, changing a User's role, or activating/deactivating a
 *     User is SUPER_ADMIN-only. Creating a SUPER_ADMIN or ANALYST account is
 *     privilege-sensitive, so we do not carve out a lesser role for any of
 *     the User-mutation endpoints, even though some of those calls (e.g.
 *     deactivating a CUSTOMER_VIEWER) are lower-risk in isolation — keeping a
 *     single bright line ("mutating the User table requires SUPER_ADMIN") is
 *     simpler to reason about and audit than a role check that varies by the
 *     target role.
 *   - Granting/revoking TenantAccess for an *existing* CUSTOMER_VIEWER user is
 *     routine customer-onboarding work analysts already do elsewhere, so it
 *     is split into its own route (tenant-access/route.ts) gated by
 *     ADMIN_USER_TENANT_ACCESS_ROLES (SUPER_ADMIN or ANALYST), independent of
 *     user creation/role-change.
 */

import { NextResponse } from 'next/server';
import {
  ForbiddenError,
  UnauthenticatedError,
  getAuthorizedSession,
  requireRole,
  type AuthorizedSession,
  type Role,
} from '@/lib/auth/rbac';
import { writeAuditLog } from '@/lib/audit/log';

/** Roles permitted to create/edit/deactivate Users and change roles. */
export const USER_MANAGEMENT_ROLES: readonly Role[] = ['SUPER_ADMIN'];

/** Roles permitted to grant/revoke TenantAccess for an existing CUSTOMER_VIEWER. */
export const TENANT_ACCESS_MANAGEMENT_ROLES: readonly Role[] = ['SUPER_ADMIN', 'ANALYST'];

/**
 * Enforces `requireRole(allowedRoles)` and, on denial, writes an audit log
 * entry recording the attempt before returning the 401/403 response.
 * `action` should identify the attempted operation, e.g. "user.create.denied".
 */
export async function requireRoleOrAudit(
  allowedRoles: readonly Role[],
  params: { action: string; targetType: string; targetId: string },
): Promise<{ session: AuthorizedSession } | { response: NextResponse }> {
  try {
    const session = await requireRole(allowedRoles);
    return { session };
  } catch (err) {
    // Best-effort: log who/what we can even when unauthenticated. An
    // unauthenticated request has no organizationId to attach the audit row
    // to, so in that case there is no tenant/org-scoped audit trail to write
    // into — we only return the 401.
    const partialSession = await getAuthorizedSession();

    if (err instanceof ForbiddenError && partialSession) {
      await writeAuditLog({
        organizationId: partialSession.organizationId,
        actorUserId: partialSession.userId,
        action: params.action,
        targetType: params.targetType,
        targetId: params.targetId,
        metadata: { reason: 'forbidden', role: partialSession.role },
      }).catch(() => {
        // Never let an audit-log failure mask the original authorization denial.
      });
      return {
        response: NextResponse.json({ error: 'Forbidden' }, { status: 403 }),
      };
    }

    if (err instanceof UnauthenticatedError) {
      return {
        response: NextResponse.json({ error: 'Unauthenticated' }, { status: 401 }),
      };
    }

    // Unexpected error type from requireRole — fail closed.
    return {
      response: NextResponse.json({ error: 'Forbidden' }, { status: 403 }),
    };
  }
}
