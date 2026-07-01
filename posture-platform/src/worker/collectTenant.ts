/**
 * Runs one full collection-and-scoring cycle for a single tenant:
 *
 *   decrypt stored credential -> collectTenantSignals (Graph) -> evaluateTenant
 *   -> deriveFindings -> computeSnapshot -> persistCycleResults
 *
 * This is the integration point between the modules built independently for
 * this project (crypto, graph, scoring, trends) — see each module's own file
 * for its internal contract. Every branch that can fail is caught and
 * audit-logged rather than left to crash the whole worker run, since one
 * tenant's collection failing must never block the others (same principle
 * `collectTenantSignals` applies at the per-signal level).
 */

import type { Tenant, TenantCredential } from '@prisma/client';

import { prisma } from '@/lib/db/client';
import { decryptCredential, type EncryptedBlob } from '@/lib/crypto/envelope';
import { collectTenantSignals, type GraphAuthConfig } from '@/lib/graph';
import { collectExoComplianceSignals } from '@/lib/powershell/collectExoCompliance';
import { collectTeamsSignals } from '@/lib/powershell/collectTeams';
import { evaluateTenant, deriveFindings } from '@/lib/scoring/engine';
import { computeSnapshot } from '@/lib/trends/snapshot';
import { persistCycleResults } from '@/lib/trends/persist';
import { getOpenFindings } from '@/lib/trends/query';
import { writeAuditLog } from '@/lib/audit/log';

export type CollectTenantResult =
  | { tenantId: string; ok: true; controlsEvaluated: number; openFindings: number }
  | { tenantId: string; ok: false; reason: string };

function toEncryptedBlob(credential: TenantCredential): EncryptedBlob {
  return {
    ciphertext: credential.ciphertext.toString('base64'),
    iv: credential.iv.toString('base64'),
    authTag: credential.authTag.toString('base64'),
    algorithm: credential.encryptionAlgorithm as EncryptedBlob['algorithm'],
    provider: credential.kmsProvider,
    kmsKeyId: credential.kmsKeyId,
    kmsKeyVersion: credential.kmsKeyVersion,
    wrappedDataKey: credential.wrappedDataKey.toString('base64'),
  };
}

/**
 * Decrypts the stored credential and shapes it into the GraphAuthConfig the
 * Graph client expects. The decrypted plaintext lives only in this function's
 * local scope and whatever `collectTenantSignals` holds in memory for the
 * lifetime of the token-minting call — it is never logged, persisted, or
 * returned from this function.
 */
async function buildAuthConfig(tenant: Tenant, credential: TenantCredential): Promise<GraphAuthConfig> {
  const plaintext = await decryptCredential(toEncryptedBlob(credential));

  if (credential.credentialType === 'CERTIFICATE') {
    return {
      kind: 'certificate',
      entraTenantId: tenant.entraTenantId,
      clientId: credential.clientId,
      certificatePem: plaintext,
    };
  }

  return {
    kind: 'secret',
    entraTenantId: tenant.entraTenantId,
    clientId: credential.clientId,
    clientSecret: plaintext,
  };
}

export async function collectAndScoreTenant(tenantId: string): Promise<CollectTenantResult> {
  const tenant = await prisma.tenant.findUnique({ where: { id: tenantId } });
  if (!tenant) {
    return { tenantId, ok: false, reason: 'tenant not found' };
  }
  if (tenant.status === 'SUSPENDED') {
    return { tenantId, ok: false, reason: 'tenant suspended' };
  }

  const credential = await prisma.tenantCredential.findFirst({
    where: { tenantId: tenant.id, isActive: true },
  });
  if (!credential) {
    await writeAuditLog({
      organizationId: tenant.organizationId,
      action: 'collection.skipped',
      targetType: 'Tenant',
      targetId: tenant.id,
      metadata: { reason: 'no_active_credential' },
    });
    return { tenantId, ok: false, reason: 'no active credential' };
  }

  let authConfig: GraphAuthConfig;
  try {
    authConfig = await buildAuthConfig(tenant, credential);
  } catch {
    // Never propagate the underlying error message here: decryptCredential already
    // sanitizes it, but this is the credential-handling boundary, so treat any
    // failure as "credentials unusable" rather than risk echoing detail upstream.
    await prisma.tenant.update({ where: { id: tenant.id }, data: { status: 'CREDENTIAL_EXPIRED' } });
    await writeAuditLog({
      organizationId: tenant.organizationId,
      action: 'collection.failed',
      targetType: 'Tenant',
      targetId: tenant.id,
      metadata: { reason: 'credential_decrypt_failed' },
    });
    return { tenantId, ok: false, reason: 'credential decrypt failed' };
  }

  const signals = await collectTenantSignals(tenant.entraTenantId, authConfig);
  // collectTenantSignals stamps the customer's Entra tenant GUID onto the result;
  // everything downstream (scoring, persistence) keys by our own internal Tenant.id.
  signals.tenantId = tenant.id;

  // Exchange Online/Security & Compliance/Teams PowerShell collection reuses the SAME
  // certificate, but only when one is configured — EXO/Teams app-only auth is
  // certificate-only (no client-secret path), unlike Graph. A secret-based tenant simply
  // gets no `exoTeams` signals; every evaluator that depends on them already degrades to
  // UNKNOWN for a missing signal rather than guessing, so this is a graceful, expected gap,
  // not an error. Both collectors already catch their own connection/collection failures
  // internally and never throw (see src/lib/powershell), consistent with the "one signal
  // source failing never blocks the rest of the cycle" principle applied everywhere else.
  if (authConfig.kind === 'certificate') {
    const [exoCompliance, teams] = await Promise.all([
      collectExoComplianceSignals(authConfig),
      collectTeamsSignals(authConfig),
    ]);
    signals.exoTeams = { exoCompliance, teams };
  }

  const results = evaluateTenant(tenant.id, signals);
  const openFindingsBefore = await getOpenFindings(tenant.id);
  // `previous` cycle's ControlResult[] isn't tracked separately — finding continuity
  // instead comes from `existingFindings` (open findings keyed by controlId), which
  // is the documented, supported way to call deriveFindings without that history.
  const findings = deriveFindings(null, results, tenant.id, openFindingsBefore);
  const snapshot = computeSnapshot(
    tenant.id,
    results,
    findings,
    signals.secureScore
      ? { current: signals.secureScore.currentScore, max: signals.secureScore.maxScore }
      : undefined
  );

  await persistCycleResults(tenant.id, results, findings, snapshot, signals.secureScore?.controlScores);

  if (tenant.status === 'ONBOARDING' || tenant.status === 'CREDENTIAL_EXPIRED') {
    await prisma.tenant.update({ where: { id: tenant.id }, data: { status: 'ACTIVE' } });
  }

  await writeAuditLog({
    organizationId: tenant.organizationId,
    action: 'collection.completed',
    targetType: 'Tenant',
    targetId: tenant.id,
    metadata: {
      controlsEvaluated: results.length,
      openFindings: findings.filter((f) => f.status === 'OPEN' || f.status === 'ACKNOWLEDGED').length,
      graphSignalErrors: signals.errors?.length ?? 0,
    },
  });

  return {
    tenantId,
    ok: true,
    controlsEvaluated: results.length,
    openFindings: findings.filter((f) => f.status === 'OPEN' || f.status === 'ACKNOWLEDGED').length,
  };
}
