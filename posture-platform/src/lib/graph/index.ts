/**
 * Public entrypoint for src/lib/graph.
 *
 * `collectTenantSignals` is the single function other modules (worker/scoring/etc.) should call:
 * given a tenant's Entra tenant id and its (already-decrypted) auth config, it builds an
 * authenticated Graph client and runs every collector, assembling a `TenantCollectionResult`.
 *
 * Design principle: a single signal being uncollectable (permission not consented, feature not
 * enabled in the tenant, transient outage that exhausted retries, etc.) must never prevent
 * collection of the other signals. Each collector is run independently and its failure is
 * captured into `result.errors` rather than thrown from `collectTenantSignals`.
 */

import type { Client } from '@microsoft/microsoft-graph-client';

import type { TenantCollectionResult } from '@/types/graph';
import { createGraphClient, type GraphAuthConfig, type GraphClientOptions } from './authClient';
import {
  collectConditionalAccessPolicies,
  collectPrivilegedRoleAssignments,
  collectRecentSignIns,
  collectRiskDetections,
  collectRiskyUsers,
  collectSecureScore,
} from './collectors';

export * from './authClient';
export * from './collectors';
export * from './pagination';
export * from './rateLimiter';

type CollectionErrors = NonNullable<TenantCollectionResult['errors']>;

/** Redacts anything that looks like a bearer token / secret from an error message before storing it. */
function toSafeErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  // Defense in depth: strip anything that looks like an Authorization header value or bearer
  // token if an upstream error message ever echoed a request header back.
  return message.replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]');
}

/**
 * Runs a single named collector, converting a thrown error into an entry in `errors` rather than
 * propagating it. Returns `undefined` on failure so the caller can conditionally assign the field.
 */
async function runCollector<T>(signal: string, errors: CollectionErrors, fn: () => Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    errors.push({ signal, message: toSafeErrorMessage(err) });
    return undefined;
  }
}

export interface CollectTenantSignalsOptions extends GraphClientOptions {
  /**
   * Inject a pre-built Graph client instead of constructing one from `authConfig` — primarily
   * useful for tests. When omitted (the normal path), a client is built via `createGraphClient`.
   */
  client?: Client;
}

/**
 * Collects every supported security signal for a single customer tenant.
 *
 * @param entraTenantId - The customer's Entra ID (Azure AD) tenant GUID. Recorded on the result
 *   for downstream correlation; not used to look up credentials (the caller already resolved
 *   `authConfig` for this tenant).
 * @param authConfig - Already-decrypted credential material for this tenant's app registration.
 *   See src/lib/graph/authClient.ts — this module never touches encryption/storage.
 */
export async function collectTenantSignals(
  entraTenantId: string,
  authConfig: GraphAuthConfig,
  options: CollectTenantSignalsOptions = {},
): Promise<TenantCollectionResult> {
  const client = options.client ?? createGraphClient(authConfig, options);
  const errors: CollectionErrors = [];

  const [secureScore, riskyUsers, riskDetections, conditionalAccessPolicies, privilegedRoleAssignments, recentSignIns] =
    await Promise.all([
      runCollector('secureScore', errors, () => collectSecureScore(client)),
      runCollector('riskyUsers', errors, () => collectRiskyUsers(client)),
      runCollector('riskDetections', errors, () => collectRiskDetections(client)),
      runCollector('conditionalAccessPolicies', errors, () => collectConditionalAccessPolicies(client)),
      runCollector('privilegedRoleAssignments', errors, () => collectPrivilegedRoleAssignments(client)),
      runCollector('recentSignIns', errors, () => collectRecentSignIns(client)),
    ]);

  const result: TenantCollectionResult = {
    tenantId: entraTenantId,
    collectedAt: new Date().toISOString(),
  };

  if (secureScore !== undefined) result.secureScore = secureScore;
  if (riskyUsers !== undefined) result.riskyUsers = riskyUsers;
  if (riskDetections !== undefined) result.riskDetections = riskDetections;
  if (conditionalAccessPolicies !== undefined) result.conditionalAccessPolicies = conditionalAccessPolicies;
  if (privilegedRoleAssignments !== undefined) result.privilegedRoleAssignments = privilegedRoleAssignments;
  if (recentSignIns !== undefined) result.recentSignIns = recentSignIns;
  if (errors.length > 0) result.errors = errors;

  return result;
}
