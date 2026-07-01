/**
 * Pure scoring engine: turns a tenant's raw collection result into
 * `ControlResult[]` (via the evaluator registry) and diffs consecutive
 * evaluation cycles into `Finding[]` transitions. No DB access here —
 * persistence lives in `src/lib/trends/persist.ts`.
 */

import { CONTROL_CATALOG } from '@/lib/controls/catalog';
import type { ControlDefinition, ControlResult, ControlStatus, Finding } from '@/types/domain';
import type { TenantCollectionResult } from '@/types/graph';
import { EVALUATOR_REGISTRY } from './evaluators';

const FAIL_LIKE_STATUSES: ControlStatus[] = ['FAIL', 'PARTIAL'];

function isFailLike(status: ControlStatus): boolean {
  return FAIL_LIKE_STATUSES.includes(status);
}

/**
 * Runs every control in CONTROL_CATALOG against the given signals, returning
 * one ControlResult per control definition (never throws for an individual
 * control — missing evaluators degrade to UNKNOWN).
 */
export function evaluateTenant(tenantId: string, signals: TenantCollectionResult): ControlResult[] {
  return CONTROL_CATALOG.map((control: ControlDefinition) => {
    const evaluator = EVALUATOR_REGISTRY[control.id];

    if (!evaluator) {
      const result: ControlResult = {
        controlId: control.id,
        tenantId,
        status: 'UNKNOWN',
        evaluatedAt: signals.collectedAt,
        detail: 'no evaluator implemented',
      };
      return result;
    }

    try {
      const outcome = evaluator(signals);
      const result: ControlResult = {
        controlId: control.id,
        tenantId,
        status: outcome.status,
        evaluatedAt: signals.collectedAt,
        detail: outcome.detail,
        evidence: outcome.evidence,
      };
      return result;
    } catch (err) {
      // An evaluator throwing is itself a data problem, not grounds to crash the whole cycle.
      const message = err instanceof Error ? err.message : String(err);
      const result: ControlResult = {
        controlId: control.id,
        tenantId,
        status: 'UNKNOWN',
        evaluatedAt: signals.collectedAt,
        detail: `evaluator threw an error: ${message}`,
      };
      return result;
    }
  });
}

const CATALOG_BY_ID: Map<string, ControlDefinition> = new Map(CONTROL_CATALOG.map((c) => [c.id, c]));

function titleFor(controlId: string): string {
  return CATALOG_BY_ID.get(controlId)?.title ?? controlId;
}

function descriptionFor(result: ControlResult): string {
  const base = CATALOG_BY_ID.get(result.controlId)?.description ?? '';
  return result.detail ? (base ? `${base} ${result.detail}` : result.detail) : base;
}

function severityFor(controlId: string): Finding['severity'] {
  return CATALOG_BY_ID.get(controlId)?.severity ?? 'MEDIUM';
}

/**
 * Diffs the previous cycle's ControlResult[] against the current cycle's to
 * produce the Finding[] that should exist going forward:
 *  - FAIL/PARTIAL controls with no existing open finding -> new OPEN finding.
 *  - FAIL/PARTIAL controls with an existing open finding -> same finding,
 *    `lastSeenAt` bumped to the current evaluation time (carried forward).
 *  - Controls that were FAIL/PARTIAL previously but are PASS (or
 *    NOT_APPLICABLE/UNKNOWN) now -> existing finding transitioned to
 *    RESOLVED with `resolvedAt` set.
 *
 * `previous` is the prior cycle's ControlResult[] (or null on the very first
 * cycle for a tenant); `existingFindings` — the tenant's current open finding
 * set — is looked up by caller and passed in via the optional third
 * parameter so this function stays pure and DB-free. When omitted, findings
 * are synthesized fresh each time a control is FAIL/PARTIAL (acceptable for
 * callers that don't yet track finding identity, e.g. tests).
 */
export function deriveFindings(
  previous: ControlResult[] | null,
  current: ControlResult[],
  tenantId: string,
  existingFindings: Finding[] = []
): Finding[] {
  const previousByControl = new Map<string, ControlResult>((previous ?? []).map((r) => [r.controlId, r]));
  const openFindingByControl = new Map<string, Finding>(
    existingFindings.filter((f) => f.status === 'OPEN' || f.status === 'ACKNOWLEDGED').map((f) => [f.controlId, f])
  );

  const now = current[0]?.evaluatedAt ?? new Date().toISOString();
  const findings: Finding[] = [];
  const currentControlIds = new Set(current.map((r) => r.controlId));

  for (const result of current) {
    const wasFailLike = previousByControl.has(result.controlId)
      ? isFailLike((previousByControl.get(result.controlId) as ControlResult).status)
      : false;
    const existingOpen = openFindingByControl.get(result.controlId);

    if (isFailLike(result.status)) {
      if (existingOpen) {
        findings.push({
          ...existingOpen,
          lastSeenAt: result.evaluatedAt,
          description: descriptionFor(result),
          severity: severityFor(result.controlId),
        });
      } else {
        findings.push({
          id: `finding-${tenantId}-${result.controlId}-${result.evaluatedAt}`,
          tenantId,
          controlId: result.controlId,
          severity: severityFor(result.controlId),
          title: titleFor(result.controlId),
          description: descriptionFor(result),
          status: 'OPEN',
          firstDetectedAt: result.evaluatedAt,
          lastSeenAt: result.evaluatedAt,
        });
      }
    } else if (existingOpen && wasFailLike) {
      // Transitioned from FAIL/PARTIAL to PASS/NOT_APPLICABLE/UNKNOWN: resolve it.
      findings.push({
        ...existingOpen,
        status: 'RESOLVED',
        lastSeenAt: result.evaluatedAt,
        resolvedAt: result.evaluatedAt,
      });
    } else if (existingOpen) {
      // Existing open finding for a control not currently fail-like and not previously
      // fail-like either (e.g. finding predates `previous`) — resolve defensively rather
      // than letting a stale open finding linger silently.
      findings.push({
        ...existingOpen,
        status: 'RESOLVED',
        lastSeenAt: result.evaluatedAt,
        resolvedAt: result.evaluatedAt,
      });
    }
  }

  // Any existing open finding for a control that no longer appears in the current cycle at
  // all (e.g. control was retired) should also be resolved rather than left dangling.
  for (const [controlId, finding] of openFindingByControl) {
    if (!currentControlIds.has(controlId)) {
      findings.push({
        ...finding,
        status: 'RESOLVED',
        lastSeenAt: now,
        resolvedAt: now,
      });
    }
  }

  return findings;
}
