/**
 * Shared helpers for the tenant onboarding API routes: consistent
 * authorization + audit-on-denial handling so every handler in this directory
 * follows the same pattern (see README.md "Security model" items 5 and 7).
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

/** Roles permitted to create tenants and submit/rotate/view credential material. */
export const TENANT_MANAGEMENT_ROLES: readonly Role[] = ['ANALYST', 'SUPER_ADMIN'];

/**
 * Enforces `requireRole(TENANT_MANAGEMENT_ROLES)` and, on denial, writes an
 * audit log entry recording the attempt before returning the 401/403 response.
 * `action` should identify the attempted operation, e.g.
 * "tenant_credential.submit.denied".
 */
export async function requireTenantManagementRoleOrAudit(params: {
  action: string;
  targetType: string;
  targetId: string;
}): Promise<{ session: AuthorizedSession } | { response: NextResponse }> {
  try {
    const session = await requireRole(TENANT_MANAGEMENT_ROLES);
    return { session };
  } catch (err) {
    // Best-effort: log who/what we can even when unauthenticated. An
    // unauthenticated request has no organizationId to attach the audit row
    // to, so in that case we only have an unauthenticated 401 response — there
    // is no tenant-scoped audit trail to write into without an organization.
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
