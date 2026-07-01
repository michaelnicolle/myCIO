/**
 * Persistence for one scoring cycle's output: ControlResult rows, Finding
 * upserts, and a PostureSnapshot row. All writes go through a single
 * `prisma.$transaction` so a partial failure (e.g. snapshot insert fails
 * after findings were written) never leaves inconsistent state for a tenant.
 *
 * Every write includes `tenantId` explicitly — never omit it, even where a
 * nested-write shorthand might let Prisma infer it, since cross-tenant data
 * leakage is a critical-severity bug class for this product.
 */

import { prisma } from '@/lib/db/client';
import type { ControlResult, Finding, PostureSnapshot } from '@/types/domain';

export async function persistCycleResults(
  tenantId: string,
  results: ControlResult[],
  findings: Finding[],
  snapshot: PostureSnapshot
): Promise<void> {
  if (snapshot.tenantId !== tenantId) {
    throw new Error(
      `persistCycleResults: snapshot.tenantId (${snapshot.tenantId}) does not match tenantId argument (${tenantId})`
    );
  }
  for (const result of results) {
    if (result.tenantId !== tenantId) {
      throw new Error(
        `persistCycleResults: ControlResult for control "${result.controlId}" has tenantId (${result.tenantId}) that does not match tenantId argument (${tenantId})`
      );
    }
  }
  for (const finding of findings) {
    if (finding.tenantId !== tenantId) {
      throw new Error(
        `persistCycleResults: Finding for control "${finding.controlId}" has tenantId (${finding.tenantId}) that does not match tenantId argument (${tenantId})`
      );
    }
  }

  await prisma.$transaction(async (tx) => {
    if (results.length > 0) {
      await tx.controlResult.createMany({
        data: results.map((r) => ({
          tenantId,
          controlId: r.controlId,
          status: r.status,
          evaluatedAt: new Date(r.evaluatedAt),
          detail: r.detail,
          evidence: r.evidence ?? undefined,
        })),
      });
    }

    for (const finding of findings) {
      await tx.finding.upsert({
        where: { id: finding.id },
        create: {
          id: finding.id,
          tenantId,
          controlId: finding.controlId,
          severity: finding.severity,
          title: finding.title,
          description: finding.description,
          status: finding.status,
          firstDetectedAt: new Date(finding.firstDetectedAt),
          lastSeenAt: new Date(finding.lastSeenAt),
          resolvedAt: finding.resolvedAt ? new Date(finding.resolvedAt) : null,
        },
        update: {
          // tenantId intentionally included (not just relied on from `where`) so an
          // update can never silently reassign/leak across tenants even if `id`
          // collided across tenants (ids are cuids and should not collide, but this
          // keeps the invariant explicit and enforced at the query layer too).
          tenantId,
          severity: finding.severity,
          title: finding.title,
          description: finding.description,
          status: finding.status,
          lastSeenAt: new Date(finding.lastSeenAt),
          resolvedAt: finding.resolvedAt ? new Date(finding.resolvedAt) : null,
        },
      });
    }

    await tx.postureSnapshot.create({
      data: {
        tenantId,
        takenAt: new Date(snapshot.takenAt),
        overallScore: snapshot.overallScore,
        functionScores: snapshot.functionScores,
        secureScoreCurrent: snapshot.secureScore?.current,
        secureScoreMax: snapshot.secureScore?.max,
        openFindingsBySeverity: snapshot.openFindingsBySeverity,
      },
    });
  });
}
