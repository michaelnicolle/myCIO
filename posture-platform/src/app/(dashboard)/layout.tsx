import type { ReactNode } from 'react';
import Link from 'next/link';
import { getAuthorizedSession } from '@/lib/auth';

/**
 * Layout for the authenticated dashboard route group (Overview, Tenants).
 *
 * Shared middleware (owned by another agent) is responsible for redirecting
 * unauthenticated requests to the login page before they ever reach here.
 * This layout still defends in depth: if session/role resolution fails for
 * any reason (expired token race, misconfiguration, etc.) we render a clear
 * "not authorized" state instead of rendering the nav/children and risking
 * any tenant-scoped data leaking through a page that assumes a session
 * exists.
 */
export default async function DashboardLayout({ children }: { children: ReactNode }) {
  const session = await getAuthorizedSession();

  if (!session) {
    return (
      <main className="min-h-screen flex items-center justify-center p-8">
        <div className="max-w-md text-center">
          <h1 className="text-xl font-semibold text-gray-900">Not authorized</h1>
          <p className="mt-2 text-sm text-gray-600">
            Your session could not be verified. Please{' '}
            <Link href="/login" className="text-indigo-600 hover:underline">
              sign in
            </Link>{' '}
            again to continue.
          </p>
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 shrink-0 border-r border-gray-200 bg-white flex flex-col">
        <div className="px-4 py-4 border-b border-gray-200">
          <span className="text-sm font-semibold text-gray-900">myCIO Posture</span>
        </div>
        <nav className="flex-1 px-2 py-4 space-y-1">
          <Link
            href="/overview"
            className="block rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
          >
            Overview
          </Link>
          <Link
            href="/tenants"
            className="block rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
          >
            Tenants
          </Link>
          {session.role === 'SUPER_ADMIN' ? (
            <Link
              href="/admin/users"
              className="block rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
            >
              Admin
            </Link>
          ) : null}
        </nav>
        <div className="px-4 py-3 border-t border-gray-200 text-xs text-gray-500">
          <p className="truncate" title={session.email}>
            {session.email}
          </p>
          <p className="mt-0.5 text-gray-400">{session.role}</p>
        </div>
      </aside>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}
