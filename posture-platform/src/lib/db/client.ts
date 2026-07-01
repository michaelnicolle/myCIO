/**
 * Prisma client singleton.
 *
 * Next.js dev mode hot-reloads server modules on every save, which would
 * otherwise instantiate a new PrismaClient (and a new connection pool) per
 * reload. We cache the instance on `globalThis` in non-production
 * environments so hot reloads reuse the same client.
 *
 * Query logging is enabled only in development to avoid leaking query
 * parameters (which may include tenant-identifying data) into production
 * logs, and to avoid the performance cost of verbose logging in prod.
 */

import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['query', 'warn', 'error'] : ['warn', 'error'],
  });
}

export const prisma: PrismaClient = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export default prisma;
