/**
 * Shared role type, kept in its own module (no other imports) so that both
 * src/lib/auth/options.ts (NextAuth config + type augmentation) and
 * src/lib/auth/rbac.ts (the requireRole guard) can depend on it without a
 * circular import between those two files.
 *
 * Mirrors the Prisma `UserRole` enum (SUPER_ADMIN / ANALYST / CUSTOMER_VIEWER).
 * Kept as a local literal union (rather than importing the Prisma enum type) so
 * this module has no hard dependency on Prisma client generation having run.
 */

export type Role = 'SUPER_ADMIN' | 'ANALYST' | 'CUSTOMER_VIEWER';

const ALL_ROLES: readonly Role[] = ['SUPER_ADMIN', 'ANALYST', 'CUSTOMER_VIEWER'];

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ALL_ROLES as readonly string[]).includes(value);
}
