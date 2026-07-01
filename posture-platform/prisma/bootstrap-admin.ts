/**
 * One-time, operator-triggered bootstrap for the FIRST portal SUPER_ADMIN.
 *
 * Why this exists: sign-in is gated on a matching, active `User` row in
 * Postgres (see src/lib/auth/options.ts `lookupPortalUser`), and creating a
 * `User` row via the admin UI/API requires an existing authenticated
 * SUPER_ADMIN session (`requireRole(['SUPER_ADMIN'])` — see
 * src/app/api/admin/users/route-helpers.ts). On a fresh deployment there are
 * zero `User` rows, so nobody can sign in to create the first one. This
 * script breaks that chicken-and-egg problem, ONE TIME, via an explicit
 * operator action — it is never run automatically as part of migrations,
 * container startup, or `prisma:seed` (see DEPLOYMENT.md "Bootstrapping the
 * first SUPER_ADMIN").
 *
 * Safety property (the reason this is safe to leave wired up permanently):
 * this script refuses to run if ANY User row with role SUPER_ADMIN already
 * exists anywhere in the database — not just for the target org. That means
 * accidentally leaving BOOTSTRAP_ADMIN_EMAIL set in the environment across a
 * redeploy cannot re-create, resurrect, or duplicate an admin account; it can
 * only ever create the very first one. If you need to add more admins later,
 * use the admin UI (an existing SUPER_ADMIN creates them) or a manual,
 * deliberate database operation — never this script.
 *
 * Usage:
 *   BOOTSTRAP_ADMIN_EMAIL=you@yourcompany.com BOOTSTRAP_ORG_NAME="Your MSP Name" \
 *     npm run bootstrap:admin
 *
 * `BOOTSTRAP_ADMIN_EMAIL` must exactly match (case-insensitively; stored
 * lowercased to match `lookupPortalUser`'s lookup) the email address of the
 * Entra ID account that will sign in — there are no passwords in this app.
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

/** Deliberately basic — just enough to catch obvious misconfiguration, not RFC 5322 exhaustive. */
const PLAUSIBLE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function readRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(
      `Missing required environment variable ${name}. Set it and re-run ` +
        '`npm run bootstrap:admin` — see DEPLOYMENT.md "Bootstrapping the first SUPER_ADMIN".',
    );
  }
  return value.trim();
}

async function main(): Promise<void> {
  const rawEmail = readRequiredEnv('BOOTSTRAP_ADMIN_EMAIL');
  const orgName = readRequiredEnv('BOOTSTRAP_ORG_NAME');

  const email = rawEmail.toLowerCase();
  if (!PLAUSIBLE_EMAIL_RE.test(email)) {
    throw new Error(
      `BOOTSTRAP_ADMIN_EMAIL ("${rawEmail}") does not look like a valid email address. ` +
        'Refusing to proceed — this must exactly match the Entra ID account that will sign in.',
    );
  }

  // Key safety check: refuse if a SUPER_ADMIN exists ANYWHERE in the database,
  // not just in the target organization. This is what makes it safe to leave
  // BOOTSTRAP_ADMIN_EMAIL set in a deploy environment indefinitely.
  const existingSuperAdmin = await prisma.user.findFirst({
    where: { role: 'SUPER_ADMIN' },
    select: { id: true, email: true, organizationId: true },
  });

  if (existingSuperAdmin) {
    console.log(
      'A SUPER_ADMIN already exists; refusing to bootstrap another one automatically ' +
        '— use the admin UI or a manual database operation if you need to add more admins.',
    );
    console.log(`  existing SUPER_ADMIN user id: ${existingSuperAdmin.id}`);
    return;
  }

  // Also guard against re-running with an email that happens to already exist
  // as a non-SUPER_ADMIN row (e.g. a CUSTOMER_VIEWER was provisioned first for
  // some reason) — never silently promote/overwrite an existing user row here.
  const existingUserByEmail = await prisma.user.findUnique({
    where: { email },
    select: { id: true, role: true },
  });
  if (existingUserByEmail) {
    throw new Error(
      `A User row already exists for ${email} (role: ${existingUserByEmail.role}). ` +
        'Refusing to modify an existing user from this bootstrap script — use the admin UI ' +
        '(once you have any working SUPER_ADMIN session) or a manual database operation instead.',
    );
  }

  const existingOrganization = await prisma.organization.findFirst({
    where: { name: orgName },
    select: { id: true, name: true },
  });
  const organization =
    existingOrganization ?? (await prisma.organization.create({ data: { name: orgName } }));

  const user = await prisma.user.create({
    data: {
      organizationId: organization.id,
      email,
      role: 'SUPER_ADMIN',
      isActive: true,
    },
    select: { id: true, email: true, role: true, isActive: true, organizationId: true },
  });

  console.log('Bootstrap complete:');
  console.log(`  organization: id=${organization.id} name="${organization.name}"`);
  console.log(`  user: id=${user.id} email=${user.email} role=${user.role} isActive=${user.isActive}`);
  console.log(
    `${user.email} can now sign in via Entra ID SSO and use the admin UI to provision everyone else.`,
  );
}

main()
  .catch((error: unknown) => {
    console.error('Bootstrap failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
