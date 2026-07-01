/**
 * Step 1 of onboarding: create a Tenant record (display name + the customer's
 * Entra tenant GUID). Uses a server action so no client JS is required for the
 * happy path. On success, redirects to the admin-consent step for the new
 * tenant.
 */

import { redirect } from 'next/navigation';
import { prisma } from '@/lib/db/client';
import { requireRole } from '@/lib/auth/rbac';
import { writeAuditLog } from '@/lib/audit/log';
import { createTenantSchema } from '@/app/api/tenants/schemas';

async function createTenantAction(formData: FormData): Promise<void> {
  'use server';

  const session = await requireRole(['ANALYST', 'SUPER_ADMIN']);

  const parsed = createTenantSchema.safeParse({
    displayName: formData.get('displayName'),
    entraTenantId: formData.get('entraTenantId'),
  });

  if (!parsed.success) {
    // Server actions can't easily return field-level errors without client JS
    // wiring; keep the wizard simple and redirect back with a query flag. A
    // richer client-validated form can be layered on later without changing
    // the API contract.
    redirect('/onboarding/tenants/new?error=invalid_input');
  }

  const { displayName, entraTenantId } = parsed.data;

  const existing = await prisma.tenant.findUnique({ where: { entraTenantId } });
  if (existing) {
    redirect('/onboarding/tenants/new?error=duplicate_tenant');
  }

  const tenant = await prisma.tenant.create({
    data: {
      organizationId: session.organizationId,
      displayName,
      entraTenantId,
      status: 'ONBOARDING',
    },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant.create',
    targetType: 'Tenant',
    targetId: tenant.id,
    metadata: { displayName: tenant.displayName, entraTenantId: tenant.entraTenantId },
  });

  redirect(`/onboarding/tenants/${tenant.id}/credentials`);
}

export default function NewTenantPage({
  searchParams,
}: {
  searchParams: { error?: string };
}) {
  const error = searchParams.error;

  return (
    <div>
      <h2 className="text-lg font-medium mb-4">1. Create the customer tenant</h2>
      <p className="text-sm text-gray-600 mb-4">
        Enter the customer&apos;s display name and their Entra ID (Azure AD) tenant GUID. You can
        find the tenant GUID in the customer&apos;s Entra admin center under Overview.
      </p>

      {error === 'invalid_input' && (
        <p className="text-sm text-red-600 mb-4" role="alert">
          Please provide a display name and a valid Entra tenant GUID.
        </p>
      )}
      {error === 'duplicate_tenant' && (
        <p className="text-sm text-red-600 mb-4" role="alert">
          A tenant with this Entra tenant ID has already been onboarded.
        </p>
      )}

      <form action={createTenantAction} className="space-y-4">
        <div>
          <label htmlFor="displayName" className="block text-sm font-medium">
            Customer display name
          </label>
          <input
            id="displayName"
            name="displayName"
            type="text"
            required
            minLength={2}
            maxLength={200}
            className="mt-1 block w-full rounded border border-gray-300 p-2"
            placeholder="Acme Corp"
          />
        </div>

        <div>
          <label htmlFor="entraTenantId" className="block text-sm font-medium">
            Entra tenant ID (GUID)
          </label>
          <input
            id="entraTenantId"
            name="entraTenantId"
            type="text"
            required
            pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>

        <button
          type="submit"
          className="rounded bg-blue-600 px-4 py-2 text-white text-sm font-medium hover:bg-blue-700"
        >
          Create tenant &amp; continue
        </button>
      </form>
    </div>
  );
}
