/**
 * Read helpers for the dashboard UI. Every query filters by `tenantId`
 * explicitly — never a bare `findMany()` — since cross-tenant data leakage
 * is a critical bug class for this multi-tenant product.
 */

import { prisma } from '@/lib/db/client';
import type { Finding, NistFunction, PostureSnapshot, Severity } from '@/types/domain';

interface PersistedSnapshotRow {
  tenantId: string;
  takenAt: Date;
  overallScore: number;
  functionScores: unknown;
  secureScoreCurrent: number | null;
  secureScoreMax: number | null;
  openFindingsBySeverity: unknown;
}

function toPostureSnapshot(row: PersistedSnapshotRow): PostureSnapshot {
  const snapshot: PostureSnapshot = {
    tenantId: row.tenantId,
    takenAt: row.takenAt.toISOString(),
    overallScore: row.overallScore,
    functionScores: row.functionScores as Record<NistFunction, number>,
    openFindingsBySeverity: row.openFindingsBySeverity as Record<Severity, number>,
  };
  if (row.secureScoreCurrent !== null && row.secureScoreMax !== null) {
    snapshot.secureScore = { current: row.secureScoreCurrent, max: row.secureScoreMax };
  }
  return snapshot;
}

interface PersistedFindingRow {
  id: string;
  tenantId: string;
  controlId: string;
  severity: Severity;
  title: string;
  description: string;
  status: Finding['status'];
  firstDetectedAt: Date;
  lastSeenAt: Date;
  resolvedAt: Date | null;
}

function toFinding(row: PersistedFindingRow): Finding {
  const finding: Finding = {
    id: row.id,
    tenantId: row.tenantId,
    controlId: row.controlId,
    severity: row.severity,
    title: row.title,
    description: row.description,
    status: row.status,
    firstDetectedAt: row.firstDetectedAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
  };
  if (row.resolvedAt) {
    finding.resolvedAt = row.resolvedAt.toISOString();
  }
  return finding;
}

/** Most recent posture snapshot for a tenant, or null if none exist yet (e.g. mid-onboarding). */
export async function getLatestSnapshot(tenantId: string): Promise<PostureSnapshot | null> {
  const row = await prisma.postureSnapshot.findFirst({
    where: { tenantId },
    orderBy: { takenAt: 'desc' },
  });
  return row ? toPostureSnapshot(row) : null;
}

/** Snapshot history for trend charts, oldest first, limited to the trailing `sinceDays` window. */
export async function getSnapshotHistory(tenantId: string, sinceDays: number): Promise<PostureSnapshot[]> {
  const since = new Date(Date.now() - sinceDays * 24 * 60 * 60 * 1000);
  const rows = await prisma.postureSnapshot.findMany({
    where: { tenantId, takenAt: { gte: since } },
    orderBy: { takenAt: 'asc' },
  });
  return rows.map(toPostureSnapshot);
}

/** All currently-open (OPEN or ACKNOWLEDGED) findings for a tenant, most recently seen first. */
export async function getOpenFindings(tenantId: string): Promise<Finding[]> {
  const rows = await prisma.finding.findMany({
    where: { tenantId, status: { in: ['OPEN', 'ACKNOWLEDGED'] } },
    orderBy: { lastSeenAt: 'desc' },
  });
  return rows.map(toFinding);
}
