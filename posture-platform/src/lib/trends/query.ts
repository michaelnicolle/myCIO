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

/** A single Microsoft Secure Score per-control result, as evaluated at one point in time. */
export interface SecureScoreControlPoint {
  controlName: string;
  controlCategory: string;
  score: number;
  evaluatedAt: string; // ISO 8601
}

/** A single control's score history, oldest first, for trend/sparkline use. */
export interface SecureScoreControlSnapshot {
  controlName: string;
  controlCategory: string;
  /** Oldest first. */
  history: Array<{ score: number; evaluatedAt: string }>;
}

/**
 * Per-control Secure Score history for a tenant over the trailing `sinceDays`
 * window, grouped by controlName so the UI can plot/inspect one control's
 * trend without re-grouping a flat list itself. Every entry is scoped to the
 * given tenantId.
 */
export async function getSecureScoreControlHistory(
  tenantId: string,
  sinceDays: number
): Promise<SecureScoreControlSnapshot[]> {
  const since = new Date(Date.now() - sinceDays * 24 * 60 * 60 * 1000);
  const rows = await prisma.secureScoreControlResult.findMany({
    where: { tenantId, evaluatedAt: { gte: since } },
    orderBy: { evaluatedAt: 'asc' },
  });

  const byControl = new Map<string, SecureScoreControlSnapshot>();
  for (const row of rows) {
    let entry = byControl.get(row.controlName);
    if (!entry) {
      entry = { controlName: row.controlName, controlCategory: row.controlCategory, history: [] };
      byControl.set(row.controlName, entry);
    }
    // Category can legitimately shift over time (Microsoft occasionally
    // re-categorizes a control); keep the most recent category label.
    entry.controlCategory = row.controlCategory;
    entry.history.push({ score: row.score, evaluatedAt: row.evaluatedAt.toISOString() });
  }

  return Array.from(byControl.values());
}

/**
 * The most recent Secure Score per-control breakdown for a tenant — i.e. what
 * is currently outstanding — ranked by score ascending (lowest-scoring /
 * biggest-gap controls first) so the dashboard can surface the highest-impact
 * recommended actions at the top. Returns an empty array if no Secure Score
 * has ever been collected for this tenant.
 */
export async function getLatestSecureScoreControls(tenantId: string): Promise<SecureScoreControlPoint[]> {
  const latest = await prisma.secureScoreControlResult.findFirst({
    where: { tenantId },
    orderBy: { evaluatedAt: 'desc' },
    select: { evaluatedAt: true },
  });
  if (!latest) return [];

  const rows = await prisma.secureScoreControlResult.findMany({
    where: { tenantId, evaluatedAt: latest.evaluatedAt },
    orderBy: { score: 'asc' },
  });

  return rows.map((row) => ({
    controlName: row.controlName,
    controlCategory: row.controlCategory,
    score: row.score,
    evaluatedAt: row.evaluatedAt.toISOString(),
  }));
}
