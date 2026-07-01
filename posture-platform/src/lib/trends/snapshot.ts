/**
 * Pure computation of a `PostureSnapshot` from a cycle's ControlResult[] and
 * open Finding[]. No DB access — persist.ts writes the result this produces.
 */

import type { ControlResult, Finding, NistFunction, PostureSnapshot, Severity } from '@/types/domain';
import { CONTROL_CATALOG } from '@/lib/controls/catalog';

const NIST_FUNCTIONS: NistFunction[] = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];
const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

/**
 * Severity weights used to pull the overall/function score down more sharply
 * for failures of more severe controls. This is a judgment call, not a
 * standard: weight is the "penalty share" a single control of that severity
 * carries relative to a LOW control failing. CRITICAL failures are worth 5x
 * as much (negatively) as LOW ones so that even a single critical failure
 * drags a mostly-passing tenant's score down noticeably, rather than the
 * score being a flat pass/fail percentage that treats "MFA not enforced" the
 * same as "no informational banner configured".
 */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFORMATIONAL: 0.5,
};

const CONTROL_SEVERITY_BY_ID: Map<string, Severity> = new Map(CONTROL_CATALOG.map((c) => [c.id, c.severity]));
const CONTROL_FUNCTION_BY_ID: Map<string, NistFunction> = new Map(CONTROL_CATALOG.map((c) => [c.id, c.nistFunction]));

function severityForControl(controlId: string): Severity {
  return CONTROL_SEVERITY_BY_ID.get(controlId) ?? 'MEDIUM';
}

function nistFunctionForControl(controlId: string): NistFunction | undefined {
  return CONTROL_FUNCTION_BY_ID.get(controlId);
}

/**
 * Weighted-score formula (applied identically for overall and per-function
 * scores):
 *
 *   score = 100 * (sum of weight for PASS controls + 0.5 * sum of weight for
 *                   PARTIAL controls)
 *                 / (sum of weight for all applicable controls)
 *
 * "Applicable" excludes NOT_APPLICABLE and UNKNOWN controls entirely (they
 * neither help nor hurt the score — an unimplemented evaluator or an
 * inherently-inapplicable control shouldn't silently tank or inflate
 * posture). PARTIAL counts as half-credit rather than a full failure or full
 * pass, since it typically represents a control that's directionally right
 * but not fully enforced (e.g. report-only CA policy). If there are no
 * applicable controls in scope, the score is defined as 0 (rather than
 * NaN/100) so an empty/broken collection cycle doesn't misrepresent an
 * unknown tenant as perfectly secure.
 */
function weightedScore(results: ControlResult[]): number {
  let earned = 0;
  let total = 0;

  for (const result of results) {
    if (result.status === 'NOT_APPLICABLE' || result.status === 'UNKNOWN') continue;
    const weight = SEVERITY_WEIGHT[severityForControl(result.controlId)];
    total += weight;
    if (result.status === 'PASS') {
      earned += weight;
    } else if (result.status === 'PARTIAL') {
      earned += weight * 0.5;
    }
    // FAIL contributes 0 to `earned` but still counts toward `total`.
  }

  if (total === 0) return 0;
  return Math.round((earned / total) * 100);
}

function computeFunctionScores(results: ControlResult[]): Record<NistFunction, number> {
  const byFunction: Record<NistFunction, ControlResult[]> = {
    GOVERN: [],
    IDENTIFY: [],
    PROTECT: [],
    DETECT: [],
    RESPOND: [],
    RECOVER: [],
  };

  for (const result of results) {
    const fn = nistFunctionForControl(result.controlId);
    if (fn) byFunction[fn].push(result);
  }

  const scores = {} as Record<NistFunction, number>;
  for (const fn of NIST_FUNCTIONS) {
    scores[fn] = weightedScore(byFunction[fn]);
  }
  return scores;
}

function computeOpenFindingsBySeverity(openFindings: Finding[]): Record<Severity, number> {
  const counts = {} as Record<Severity, number>;
  for (const severity of SEVERITIES) counts[severity] = 0;

  for (const finding of openFindings) {
    if (finding.status !== 'OPEN' && finding.status !== 'ACKNOWLEDGED') continue;
    counts[finding.severity] += 1;
  }
  return counts;
}

export function computeSnapshot(
  tenantId: string,
  results: ControlResult[],
  openFindings: Finding[],
  secureScore?: { current: number; max: number }
): PostureSnapshot {
  const takenAt = results[0]?.evaluatedAt ?? new Date().toISOString();

  const snapshot: PostureSnapshot = {
    tenantId,
    takenAt,
    overallScore: weightedScore(results),
    functionScores: computeFunctionScores(results),
    openFindingsBySeverity: computeOpenFindingsBySeverity(openFindings),
  };

  if (secureScore) {
    snapshot.secureScore = secureScore;
  }

  return snapshot;
}
