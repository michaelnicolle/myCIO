/**
 * Admin > Users > New: create a portal User (email, name, role), and — for
 * CUSTOMER_VIEWER — grant TenantAccess to one or more Tenants in the same
 * organization, in the same operation.
 *
 * Gated SUPER_ADMIN-only, matching src/app/api/admin/users/route.ts.
 *
 * Uses a server action (no client JS required for the happy path), same
 * convention as src/app/(onboarding)/onboarding/tenants/new/page.tsx.
 */

import { redirect } from 'next/navigation';
import Link from 'next/link';
import { ForbiddenError, UnauthenticatedError, requireRole } from '@/lib/auth/rbac';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { createUserSchema } from '@/app/api/admin/users/schemas';

async function createUserAction(formData: FormData): Promise<void> {
  'use server';

  const session = await requireRole(['SUPER_ADMIN']);

  const role = formData.get('role');
  const tenantIds = formData.getAll('tenantIds').map((v) => String(v));

  const parsed = createUserSchema.safeParse({
    email: formData.get('email'),
    name: formData.get('name') || undefined,
    role,
    tenantIds: tenantIds.length > 0 ? tenantIds : undefined,
  });

  if (!parsed.success) {
    redirect('/admin/users/new?error=invalid_input');
  }

  const { email, name, role: parsedRole, tenantIds: parsedTenantIds } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    redirect('/admin/users/new?error=duplicate_email');
  }

  const grantTenantIds = parsedRole === 'CUSTOMER_VIEWER' ? parsedTenantIds ?? [] : [];

  if (grantTenantIds.length > 0) {
    const validTenants = await prisma.tenant.findMany({
      where: { id: { in: grantTenantIds }, organizationId: session.organizationId },
      select: { id: true },
    });
    if (validTenants.length !== grantTenantIds.length) {
      redirect('/admin/users/new?error=invalid_tenants');
    }
  }

  const user = await prisma.$transaction(async (tx) => {
    const created = await tx.user.create({
      data: {
        organizationId: session.organizationId,
        email,
        name: name ?? null,
        role: parsedRole,
        isActive: true,
      },
    });

    if (grantTenantIds.length > 0) {
      await tx.tenantAccess.createMany({
        data: grantTenantIds.map((tenantId) => ({ userId: created.id, tenantId })),
      });
    }

    return created;
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'user.create',
    targetType: 'User',
    targetId: user.id,
    metadata: { email: user.email, role: user.role, grantedTenantIds: grantTenantIds },
  });

  redirect(`/admin/users/${user.id}`);
}

export default async function NewUserPage({
  searchParams,
}: {
  searchParams: { error?: string };
}) {
  let session;
  try {
    session = await requireRole(['SUPER_ADMIN']);
  } catch (err) {
    if (err instanceof UnauthenticatedError) {
      redirect('/login');
    }
    if (err instanceof ForbiddenError) {
      redirect('/overview');
    }
    throw err;
  }

  const tenants = await prisma.tenant.findMany({
    where: { organizationId: session.organizationId },
    orderBy: { displayName: 'asc' },
    select: { id: true, displayName: true },
  });

  const error = searchParams.error;

  return (
    <main className="p-8 max-w-2xl">
      <Link href="/admin/users" className="text-sm text-indigo-600 hover:underline">
        &larr; Back to users
      </Link>

      <h1 className="mt-2 text-2xl font-semibold text-gray-900">Add user</h1>
      <p className="mt-1 text-sm text-gray-600">
        This pre-authorizes an email address and role for portal sign-in. Users authenticate via
        their organization&apos;s Entra ID (Microsoft 365) single sign-on &mdash; there is no
        separate password or invite email. Once created, this person can sign in with their
        existing Entra ID account matching this email address.
      </p>

      {error === 'invalid_input' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          Please provide a valid email address and role.
        </p>
      )}
      {error === 'duplicate_email' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          A user with this email already exists.
        </p>
      )}
      {error === 'invalid_tenants' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          One or more selected tenants were not found in your organization.
        </p>
      )}

      <form action={createUserAction} className="mt-6 space-y-4">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-900">
            Email address
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            maxLength={320}
            className="mt-1 block w-full rounded border border-gray-300 p-2"
            placeholder="jane.doe@customer.com"
          />
          <p className="mt-1 text-xs text-gray-500">
            Must exactly match the email of the person&apos;s Entra ID account.
          </p>
        </div>

        <div>
          <label htmlFor="name" className="block text-sm font-medium text-gray-900">
            Display name (optional)
          </label>
          <input
            id="name"
            name="name"
            type="text"
            maxLength={200}
            className="mt-1 block w-full rounded border border-gray-300 p-2"
            placeholder="Jane Doe"
          />
        </div>

        <div>
          <label htmlFor="role" className="block text-sm font-medium text-gray-900">
            Role
          </label>
          <select
            id="role"
            name="role"
            required
            defaultValue="CUSTOMER_VIEWER"
            className="mt-1 block w-full rounded border border-gray-300 p-2"
          >
            <option value="CUSTOMER_VIEWER">Customer viewer</option>
            <option value="ANALYST">Analyst (MSP staff)</option>
            <option value="SUPER_ADMIN">Super admin (MSP staff)</option>
          </select>
          <p className="mt-1 text-xs text-gray-500">
            Analysts and super admins see every tenant your organization manages. Customer
            viewers must be granted access to specific tenants below.
          </p>
        </div>

        <div>
          <span className="block text-sm font-medium text-gray-900">
            Tenant access (customer viewers only)
          </span>
          <p className="mt-1 text-xs text-gray-500">
            Only applies if the role above is &ldquo;Customer viewer&rdquo;. Select every tenant
            this person should be able to see.
          </p>
          {tenants.length === 0 ? (
            <p className="mt-2 text-sm text-gray-500">No tenants onboarded yet.</p>
          ) : (
            <div className="mt-2 max-h-64 space-y-1 overflow-y-auto rounded border border-gray-300 p-2">
              {tenants.map((tenant) => (
                <label key={tenant.id} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-gray-50">
                  <input type="checkbox" name="tenantIds" value={tenant.id} className="rounded border-gray-300" />
                  {tenant.displayName}
                </label>
              ))}
            </div>
          )}
        </div>

        <button
          type="submit"
          className="rounded bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Create user
        </button>
      </form>
    </main>
  );
}
