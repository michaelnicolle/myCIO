/**
 * Background collection worker entrypoint (`npm run worker`).
 *
 * Runs independently of the Next.js web process — Graph collection cycles can
 * take longer than a serverless request budget, so this is a long-lived Node
 * process scheduled by cron (COLLECTION_INTERVAL_CRON, default every 6 hours).
 *
 * On each tick: load every non-suspended tenant, run a collection-and-scoring
 * cycle per tenant (bounded concurrency so one slow/rate-limited tenant
 * doesn't serialize the rest), and log a summary. One tenant failing never
 * aborts the run for the others — see collectTenant.ts.
 */

import cron from 'node-cron';

import { prisma } from '@/lib/db/client';
import { collectAndScoreTenant } from './collectTenant';

const MAX_CONCURRENT_TENANTS = 5;
const DEFAULT_CRON = '0 */6 * * *';

async function runCycle(): Promise<void> {
  const startedAt = Date.now();
  const tenants = await prisma.tenant.findMany({
    where: { status: { not: 'SUSPENDED' } },
    select: { id: true },
  });

  // eslint-disable-next-line no-console
  console.log(`[worker] starting collection cycle for ${tenants.length} tenant(s)`);

  const queue = [...tenants];
  let succeeded = 0;
  let failed = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const next = queue.shift();
      if (!next) return;

      const result = await collectAndScoreTenant(next.id).catch(
        (err): { tenantId: string; ok: false; reason: string } => ({
          tenantId: next.id,
          ok: false,
          reason: err instanceof Error ? err.message : 'unknown error',
        })
      );

      if (result.ok) {
        succeeded += 1;
      } else {
        failed += 1;
        // eslint-disable-next-line no-console
        console.warn(`[worker] tenant ${result.tenantId} collection skipped/failed: ${result.reason}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_TENANTS, tenants.length) }, worker));

  const elapsedSeconds = ((Date.now() - startedAt) / 1000).toFixed(1);
  // eslint-disable-next-line no-console
  console.log(
    `[worker] collection cycle complete in ${elapsedSeconds}s (${succeeded} succeeded, ${failed} skipped/failed)`
  );
}

function main(): void {
  const schedule = process.env['COLLECTION_INTERVAL_CRON'] || DEFAULT_CRON;
  if (!cron.validate(schedule)) {
    throw new Error(`Invalid COLLECTION_INTERVAL_CRON expression: "${schedule}"`);
  }

  // eslint-disable-next-line no-console
  console.log(`[worker] scheduling collection cycles with cron "${schedule}"`);
  cron.schedule(schedule, () => {
    runCycle().catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[worker] collection cycle threw unexpectedly:', err instanceof Error ? err.message : err);
    });
  });

  // Also run once immediately on startup rather than waiting for the first tick.
  runCycle().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[worker] initial collection cycle threw unexpectedly:', err instanceof Error ? err.message : err);
  });
}

main();
