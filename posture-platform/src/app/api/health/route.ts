/**
 * Unauthenticated health check for platform monitoring (Railway "Healthcheck
 * Path", uptime probes, load balancers). Deliberately excluded from
 * authentication/RBAC — see src/middleware.ts (or equivalent) if this route
 * is ever wrapped in a global auth gate.
 *
 * Verifies DB connectivity with a trivial query. Response bodies are
 * intentionally minimal: no stack traces, connection strings, error messages,
 * or other internals are ever included, since this route is reachable
 * without auth.
 */

import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db/client';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return NextResponse.json({ status: 'ok' }, { status: 200 });
  } catch {
    // Do not include the caught error's message/stack here — it may contain
    // connection details. Full details are still available in server logs
    // via Prisma's own error logging (see src/lib/db/client.ts).
    return NextResponse.json({ status: 'unavailable' }, { status: 503 });
  }
}
