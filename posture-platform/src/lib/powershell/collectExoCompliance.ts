/**
 * Thin orchestrator around the Exchange Online / Security & Compliance PowerShell
 * collector script. Mirrors `collectAndScoreTenant`'s "one failing signal source never
 * blocks the whole cycle" philosophy (src/worker/collectTenant.ts) at the top level: a
 * full connection failure (e.g. the Exchange.ManageAsApp permission / Exchange
 * Administrator role hasn't been granted yet for this tenant) degrades gracefully to a
 * result carrying only `errors`, rather than throwing and crashing the worker.
 */

import type { ExoComplianceCollectionResult } from '@/types/exoTeams';
import { runPowerShellCollector } from './bridge';
import type { GraphCertificateAuthConfig } from '@/lib/graph/authClient';

const SCRIPT_RELATIVE_PATH = 'scripts/Collect-ExoComplianceSignals.ps1';
const TIMEOUT_MS = 180_000;

/** Redacts anything resembling secret material; defense-in-depth, mirroring src/lib/graph/index.ts. */
function toSafeErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return message.length > 500 ? `${message.slice(0, 500)}...(truncated)` : message;
}

/**
 * Collects DKIM/DMARC, transport rules, remote domains, org mail config, mailbox audit
 * bypass, sharing policies, and Defender for Office 365 (hosted content/connection
 * filter, anti-phish, Safe Attachments, Safe Links) policies, plus unified audit log
 * ingestion state, for one tenant via a certificate-authenticated Exchange Online /
 * Security & Compliance PowerShell session.
 *
 * Never throws: any failure to even connect (missing role/permission grant, expired
 * cert, network issue reaching the child `pwsh` process, timeout, etc.) is caught here
 * and returned as `{ collectedAt, errors: [{ signal: 'connection', message }] }` instead
 * — the caller can persist this result exactly like a successful one.
 */
export async function collectExoComplianceSignals(
  authConfig: GraphCertificateAuthConfig,
): Promise<ExoComplianceCollectionResult> {
  try {
    return await runPowerShellCollector<ExoComplianceCollectionResult>(
      SCRIPT_RELATIVE_PATH,
      authConfig,
      TIMEOUT_MS,
    );
  } catch (err) {
    return {
      collectedAt: new Date().toISOString(),
      errors: [{ signal: 'connection', message: toSafeErrorMessage(err) }],
    };
  }
}
