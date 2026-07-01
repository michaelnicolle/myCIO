/**
 * Admin > Users: list every portal User in the caller's Organization, with
 * role badges and active/inactive status.
 *
 * Gated SUPER_ADMIN-only, matching the API routes in
 * src/app/api/admin/users — see src/app/api/admin/users/route-helpers.ts for
 * the full authorization-split rationale. This page enforces the same rule
 * at the page level (in addition to the API routes enforcing it
 * independently) so a CUSTOMER_VIEWER/ANALYST never even sees the admin
 * shell — defense in depth, not a substitute for the API-level check.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { ForbiddenError, UnauthenticatedError, requireRole } from '@/lib/auth/rbac';
import { prisma } from '@/lib/db/client';
import type { Role } from '@/lib/auth/rbac';

export const dynamic = 'force-dynamic';

const ROLE_BADGE_STYLES: Record<Role, string> = {
  SUPER_ADMIN: 'bg-purple-100 text-purple-800 ring-purple-600/20',
  ANALYST: 'bg-blue-100 text-blue-800 ring-blue-600/20',
  CUSTOMER_VIEWER: 'bg-gray-100 text-gray-700 ring-gray-500/20',
};

function RoleBadge({ role }: { role: Role }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${ROLE_BADGE_STYLES[role]}`}
    >
      {role.replace('_', ' ')}
    </span>
  );
}

function StatusBadge({ isActive }: { isActive: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
        isActive
          ? 'bg-emerald-100 text-emerald-800 ring-emerald-600/20'
          : 'bg-red-100 text-red-800 ring-red-600/20'
      }`}
    >
      {isActive ? 'Active' : 'Inactive'}
    </span>
  );
}

export default async function AdminUsersPage() {
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

  const users = await prisma.user.findMany({
    where: { organizationId: session.organizationId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      isActive: true,
      createdAt: true,
      _count: { select: { tenantAccess: true } },
    },
  });

  return (
    <main className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Users</h1>
          <p className="mt-1 text-sm text-gray-600">
            Portal users authorized to sign in via Entra ID SSO, and their roles.
          </p>
        </div>
        <Link
          href="/admin/users/new"
          className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Add user
        </Link>
      </div>

      {users.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 bg-white p-12 text-center">
          <h2 className="text-lg font-medium text-gray-900">No users yet</h2>
          <p className="mt-2 text-sm text-gray-600">
            Add a portal user to authorize their Entra ID account to sign in.
          </p>
          <Link
            href="/admin/users/new"
            className="mt-4 inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            Add user
          </Link>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                  Email
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                  Name
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                  Role
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                  Status
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium uppercase tracking-wide text-gray-500">
                  Tenant grants
                </th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map((user) => (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="whitespace-nowrap px-4 py-3 text-sm text-gray-900">{user.email}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm text-gray-600">
                    {user.name ?? <span className="text-gray-400">&mdash;</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <RoleBadge role={user.role} />
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <StatusBadge isActive={user.isActive} />
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-sm text-gray-600">
                    {user.role === 'CUSTOMER_VIEWER' ? user._count.tenantAccess : <span className="text-gray-400">n/a</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-right text-sm">
                    <Link href={`/admin/users/${user.id}`} className="text-indigo-600 hover:underline">
                      Manage
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
