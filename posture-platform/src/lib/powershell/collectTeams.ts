/**
 * Thin orchestrator around the Microsoft Teams PowerShell collector script. Same
 * graceful-degradation philosophy as `collectExoComplianceSignals` (see that file and
 * src/worker/collectTenant.ts): a connection failure (e.g. the Teams Administrator role
 * hasn't been granted yet for this tenant) never throws — it degrades to a result
 * carrying only `errors`.
 */

import type { TeamsCollectionResult } from '@/types/exoTeams';
import { runPowerShellCollector } from './bridge';
import type { GraphCertificateAuthConfig } from '@/lib/graph/authClient';

const SCRIPT_RELATIVE_PATH = 'scripts/Collect-TeamsSignals.ps1';
const TIMEOUT_MS = 120_000;

/** Redacts anything resembling secret material; defense-in-depth, mirroring src/lib/graph/index.ts. */
function toSafeErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return message.length > 500 ? `${message.slice(0, 500)}...(truncated)` : message;
}

/**
 * Collects Teams federation config, meeting/messaging policies, and client config for
 * one tenant via a certificate-authenticated Microsoft Teams PowerShell session.
 *
 * Never throws: any failure to even connect is caught here and returned as
 * `{ collectedAt, errors: [{ signal: 'connection', message }] }` instead.
 */
export async function collectTeamsSignals(
  authConfig: GraphCertificateAuthConfig,
): Promise<TeamsCollectionResult> {
  try {
    return await runPowerShellCollector<TeamsCollectionResult>(SCRIPT_RELATIVE_PATH, authConfig, TIMEOUT_MS);
  } catch (err) {
    return {
      collectedAt: new Date().toISOString(),
      errors: [{ signal: 'connection', message: toSafeErrorMessage(err) }],
    };
  }
}
