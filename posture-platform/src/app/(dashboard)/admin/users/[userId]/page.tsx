/**
 * Admin > Users > [userId]: change role, toggle active, and manage
 * TenantAccess grants for CUSTOMER_VIEWER users.
 *
 * Role/active changes are gated SUPER_ADMIN-only. TenantAccess grant/revoke
 * on this page is also invoked by a SUPER_ADMIN here (this page lives inside
 * the SUPER_ADMIN-only /admin/users tree), but the underlying API route
 * (src/app/api/admin/users/[userId]/tenant-access/route.ts) additionally
 * allows ANALYST — see that route's docstring. Analysts doing routine
 * tenant-access grants would call that API directly or from a future
 * lighter-weight surface; this admin page's own actions still require
 * SUPER_ADMIN since it shares a layout/action set with role changes.
 */

import { notFound, redirect } from 'next/navigation';
import Link from 'next/link';
import { ForbiddenError, UnauthenticatedError, requireRole } from '@/lib/auth/rbac';
import { prisma } from '@/lib/db/client';
import { writeAuditLog } from '@/lib/audit/log';
import { updateUserSchema, tenantAccessActionSchema } from '@/app/api/admin/users/schemas';

export const dynamic = 'force-dynamic';

interface PageProps {
  params: { userId: string };
  searchParams: { error?: string; ok?: string };
}

async function updateRoleAction(userId: string, formData: FormData): Promise<void> {
  'use server';

  const session = await requireRole(['SUPER_ADMIN']);

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
  });
  if (!target) {
    notFound();
  }

  const parsed = updateUserSchema.safeParse({ role: formData.get('role') });
  if (!parsed.success) {
    redirect(`/admin/users/${userId}?error=invalid_input`);
  }

  const { role } = parsed.data;
  const previousRole = target.role;

  if (userId === session.userId && role !== undefined && role !== previousRole) {
    // Footgun prevention: a SUPER_ADMIN must not be able to change their own
    // role — could otherwise leave the organization with zero SUPER_ADMIN
    // accounts and no way to self-recover via this UI.
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.role_change.self_denied',
      targetType: 'User',
      targetId: userId,
      metadata: { reason: 'cannot_change_own_role', attemptedRole: role },
    }).catch(() => {});
    redirect(`/admin/users/${userId}?error=cannot_change_own_role`);
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { role },
  });

  if (role !== undefined && role !== previousRole) {
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.role_change',
      targetType: 'User',
      targetId: updated.id,
      metadata: { previousRole, newRole: role },
    });
  }

  redirect(`/admin/users/${userId}?ok=role_updated`);
}

async function toggleActiveAction(userId: string, nextIsActive: boolean): Promise<void> {
  'use server';

  const session = await requireRole(['SUPER_ADMIN']);

  if (userId === session.userId && nextIsActive === false) {
    // Footgun prevention: a SUPER_ADMIN must not be able to deactivate their
    // own account through this UI.
    await writeAuditLog({
      organizationId: session.organizationId,
      actorUserId: session.userId,
      action: 'user.deactivate.self_denied',
      targetType: 'User',
      targetId: userId,
      metadata: { reason: 'cannot_deactivate_self' },
    }).catch(() => {});
    redirect(`/admin/users/${userId}?error=cannot_deactivate_self`);
  }

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
  });
  if (!target) {
    notFound();
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { isActive: nextIsActive },
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: nextIsActive ? 'user.activate' : 'user.deactivate',
    targetType: 'User',
    targetId: updated.id,
    metadata: { previousIsActive: target.isActive },
  });

  redirect(`/admin/users/${userId}?ok=status_updated`);
}

async function grantTenantAccessAction(userId: string, formData: FormData): Promise<void> {
  'use server';

  const session = await requireRole(['SUPER_ADMIN']);

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
    select: { id: true, role: true, organizationId: true },
  });
  if (!target) {
    notFound();
  }
  if (target.role !== 'CUSTOMER_VIEWER') {
    redirect(`/admin/users/${userId}?error=not_customer_viewer`);
  }

  const parsed = tenantAccessActionSchema.safeParse({ tenantId: formData.get('tenantId') });
  if (!parsed.success) {
    redirect(`/admin/users/${userId}?error=invalid_input`);
  }
  const { tenantId } = parsed.data;

  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: target.organizationId },
    select: { id: true },
  });
  if (!tenant) {
    redirect(`/admin/users/${userId}?error=invalid_tenants`);
  }

  const grant = await prisma.tenantAccess.upsert({
    where: { userId_tenantId: { userId, tenantId } },
    create: { userId, tenantId },
    update: {},
  });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_access.grant',
    targetType: 'TenantAccess',
    targetId: grant.id,
    metadata: { userId, tenantId },
  });

  redirect(`/admin/users/${userId}?ok=access_granted`);
}

async function revokeTenantAccessAction(userId: string, tenantId: string): Promise<void> {
  'use server';

  const session = await requireRole(['SUPER_ADMIN']);

  const target = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
    select: { id: true },
  });
  if (!target) {
    notFound();
  }

  const grant = await prisma.tenantAccess.findFirst({ where: { userId, tenantId } });
  if (!grant) {
    redirect(`/admin/users/${userId}?error=grant_not_found`);
  }

  await prisma.tenantAccess.delete({ where: { id: grant.id } });

  await writeAuditLog({
    organizationId: session.organizationId,
    actorUserId: session.userId,
    action: 'tenant_access.revoke',
    targetType: 'TenantAccess',
    targetId: grant.id,
    metadata: { userId, tenantId },
  });

  redirect(`/admin/users/${userId}?ok=access_revoked`);
}

export default async function EditUserPage({ params, searchParams }: PageProps) {
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

  const { userId } = params;

  const user = await prisma.user.findFirst({
    where: { id: userId, organizationId: session.organizationId },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      tenantAccess: {
        select: { id: true, tenantId: true, tenant: { select: { id: true, displayName: true } } },
        orderBy: { createdAt: 'desc' },
      },
    },
  });

  if (!user) {
    notFound();
  }

  const grantedTenantIds = new Set(user.tenantAccess.map((a) => a.tenantId));
  const availableTenants =
    user.role === 'CUSTOMER_VIEWER'
      ? await prisma.tenant.findMany({
          where: { organizationId: session.organizationId, id: { notIn: [...grantedTenantIds] } },
          orderBy: { displayName: 'asc' },
          select: { id: true, displayName: true },
        })
      : [];

  const isSelf = user.id === session.userId;
  const error = searchParams.error;
  const ok = searchParams.ok;

  const updateRoleWithId = updateRoleAction.bind(null, userId);
  const grantTenantAccessWithId = grantTenantAccessAction.bind(null, userId);

  return (
    <main className="p-8 max-w-2xl">
      <Link href="/admin/users" className="text-sm text-indigo-600 hover:underline">
        &larr; Back to users
      </Link>

      <div className="mt-2 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">{user.email}</h1>
          <p className="mt-1 text-sm text-gray-600">
            {user.name ?? 'No display name set'} &middot; Added {new Date(user.createdAt).toLocaleDateString()}
          </p>
        </div>
      </div>

      {error === 'invalid_input' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          Invalid input.
        </p>
      )}
      {error === 'cannot_deactivate_self' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          You cannot deactivate your own account.
        </p>
      )}
      {error === 'cannot_change_own_role' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          You cannot change your own role.
        </p>
      )}
      {error === 'not_customer_viewer' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          Tenant access only applies to customer viewer users.
        </p>
      )}
      {error === 'invalid_tenants' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          That tenant was not found in your organization.
        </p>
      )}
      {error === 'grant_not_found' && (
        <p className="mt-4 text-sm text-red-600" role="alert">
          That tenant access grant no longer exists.
        </p>
      )}
      {ok && (
        <p className="mt-4 text-sm text-emerald-700" role="status">
          Saved.
        </p>
      )}

      <section className="mt-6 rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-medium text-gray-900">Role</h2>
        <form action={updateRoleWithId} className="mt-3 flex items-end gap-3">
          <div>
            <label htmlFor="role" className="block text-xs font-medium text-gray-700">
              Role
            </label>
            <select
              id="role"
              name="role"
              defaultValue={user.role}
              className="mt-1 block rounded border border-gray-300 p-2 text-sm"
            >
              <option value="CUSTOMER_VIEWER">Customer viewer</option>
              <option value="ANALYST">Analyst (MSP staff)</option>
              <option value="SUPER_ADMIN">Super admin (MSP staff)</option>
            </select>
          </div>
          <button
            type="submit"
            className="rounded bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            Update role
          </button>
        </form>
        <p className="mt-2 text-xs text-gray-500">
          Changing to/from customer viewer changes how tenant access is enforced: analysts and
          super admins see every tenant your organization manages, while customer viewers only see
          tenants explicitly granted below.
        </p>
      </section>

      <section className="mt-6 rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-medium text-gray-900">Status</h2>
        <p className="mt-1 text-sm text-gray-600">
          Current status:{' '}
          <span className={user.isActive ? 'font-medium text-emerald-700' : 'font-medium text-red-700'}>
            {user.isActive ? 'Active' : 'Inactive'}
          </span>
          . Inactive users cannot sign in even with a valid Entra ID account.
        </p>
        {isSelf ? (
          <p className="mt-3 text-xs text-gray-500">You cannot deactivate your own account.</p>
        ) : (
          <form action={toggleActiveAction.bind(null, userId, !user.isActive)} className="mt-3">
            <button
              type="submit"
              className={`rounded px-3 py-2 text-sm font-medium text-white ${
                user.isActive ? 'bg-red-600 hover:bg-red-500' : 'bg-emerald-600 hover:bg-emerald-500'
              }`}
            >
              {user.isActive ? 'Deactivate user' : 'Reactivate user'}
            </button>
          </form>
        )}
      </section>

      {user.role === 'CUSTOMER_VIEWER' && (
        <section className="mt-6 rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
          <h2 className="text-sm font-medium text-gray-900">Tenant access</h2>
          <p className="mt-1 text-sm text-gray-600">
            This customer viewer can only see the tenants explicitly listed below.
          </p>

          {user.tenantAccess.length === 0 ? (
            <p className="mt-3 text-sm text-gray-500">No tenants granted yet.</p>
          ) : (
            <ul className="mt-3 divide-y divide-gray-100">
              {user.tenantAccess.map((grant) => (
                <li key={grant.id} className="flex items-center justify-between py-2 text-sm">
                  <span className="text-gray-900">{grant.tenant.displayName}</span>
                  <form action={revokeTenantAccessAction.bind(null, userId, grant.tenantId)}>
                    <button type="submit" className="text-red-600 hover:underline">
                      Revoke
                    </button>
                  </form>
                </li>
              ))}
            </ul>
          )}

          {availableTenants.length > 0 && (
            <form action={grantTenantAccessWithId} className="mt-4 flex items-end gap-3">
              <div className="flex-1">
                <label htmlFor="tenantId" className="block text-xs font-medium text-gray-700">
                  Grant access to
                </label>
                <select
                  id="tenantId"
                  name="tenantId"
                  className="mt-1 block w-full rounded border border-gray-300 p-2 text-sm"
                >
                  {availableTenants.map((tenant) => (
                    <option key={tenant.id} value={tenant.id}>
                      {tenant.displayName}
                    </option>
                  ))}
                </select>
              </div>
              <button
                type="submit"
                className="rounded bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500"
              >
                Grant
              </button>
            </form>
          )}
        </section>
      )}
    </main>
  );
}
