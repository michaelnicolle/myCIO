/**
 * Seeds the control catalog (prisma/../src/lib/controls/catalog.ts) into the
 * database. Idempotent: uses upsert keyed on stable ids, and reconciles
 * ControlMapping rows on every run so re-running after editing the catalog
 * converges the database to match the in-code source of truth (including
 * removing mappings that were deleted from the catalog).
 *
 * Run via `npm run prisma:seed` (tsx prisma/seed.ts).
 */

import { PrismaClient } from '@prisma/client';
import { CONTROL_CATALOG } from '../src/lib/controls/catalog';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  console.log(`Seeding ${CONTROL_CATALOG.length} control definitions...`);

  for (const control of CONTROL_CATALOG) {
    await prisma.controlDefinition.upsert({
      where: { id: control.id },
      create: {
        id: control.id,
        title: control.title,
        description: control.description,
        nistFunction: control.nistFunction,
        severity: control.severity,
        requiredSignals: control.requiredSignals,
      },
      update: {
        title: control.title,
        description: control.description,
        nistFunction: control.nistFunction,
        severity: control.severity,
        requiredSignals: control.requiredSignals,
      },
    });

    // Reconcile mappings for this control: delete any rows no longer present
    // in the catalog, then upsert the current set. Wrapped so a partial
    // failure doesn't leave mappings half-updated.
    const currentKeys = control.mappings.map((m) => `${m.framework}:${m.controlId}`);

    // `NOT: []` would match everything (deleting all mappings), so when a
    // control has no mappings, delete unconditionally by controlId instead.
    const staleMappingsFilter =
      control.mappings.length > 0
        ? {
            controlId: control.id,
            NOT: control.mappings.map((m) => ({
              framework: m.framework,
              frameworkControlId: m.controlId,
            })),
          }
        : { controlId: control.id };

    await prisma.$transaction([
      prisma.controlMapping.deleteMany({ where: staleMappingsFilter }),
      ...control.mappings.map((m) =>
        prisma.controlMapping.upsert({
          where: {
            controlId_framework_frameworkControlId: {
              controlId: control.id,
              framework: m.framework,
              frameworkControlId: m.controlId,
            },
          },
          create: {
            controlId: control.id,
            framework: m.framework,
            frameworkControlId: m.controlId,
          },
          update: {},
        }),
      ),
    ]);

    console.log(`  upserted ${control.id} (${currentKeys.length} mapping(s))`);
  }

  console.log('Control catalog seed complete.');
}

main()
  .catch((error: unknown) => {
    console.error('Seed failed:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
