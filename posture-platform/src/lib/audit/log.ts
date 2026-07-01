/**
 * Append-only audit log writer. See README.md "Security model" item 7: all
 * administrative actions (tenant creation, credential submission/rotation,
 * role changes, and denied/unauthorized attempts at any of those) must call
 * writeAuditLog on both success and failure paths.
 *
 * This module intentionally accepts only structured metadata (Record<string,
 * unknown>) — callers must never pass plaintext secrets/keys in `metadata`.
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@/lib/db/client';

export interface WriteAuditLogInput {
  organizationId: string;
  /** Null/undefined for system/automation-initiated actions (no human actor). */
  actorUserId?: string | null;
  /**
   * Stable, greppable action identifier, e.g. "tenant.create",
   * "tenant_credential.submit", "tenant_credential.rotate",
   * "tenant_credential.view.denied", "user.role_change".
   */
  action: string;
  /** e.g. "Tenant", "TenantCredential", "User". */
  targetType: string;
  targetId: string;
  /**
   * Additional structured context. MUST NOT contain plaintext credential
   * material, DEKs, wrapped keys, or full session tokens — only
   * non-sensitive descriptive fields (e.g. credentialType, previousRole).
   */
  metadata?: Record<string, unknown>;
}

/**
 * Writes one audit log row. This never throws away failures silently: if the
 * write itself fails, the error is logged (without leaking `metadata` contents
 * beyond what the caller already supplied — callers are responsible for
 * keeping metadata non-sensitive) and re-thrown, so a caller that depends on
 * audit-then-respond semantics can decide how to handle an audit outage
 * (e.g. failing closed for high-risk actions like credential rotation).
 */
export async function writeAuditLog(input: WriteAuditLogInput): Promise<void> {
  const { organizationId, actorUserId, action, targetType, targetId, metadata } = input;

  try {
    await prisma.auditLog.create({
      data: {
        organizationId,
        actorUserId: actorUserId ?? null,
        action,
        targetType,
        targetId,
        metadata: metadata as Prisma.InputJsonValue | undefined,
      },
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `Failed to write audit log for action="${action}" targetType="${targetType}" targetId="${targetId}":`,
      err instanceof Error ? err.message : err,
    );
    throw err;
  }
}
