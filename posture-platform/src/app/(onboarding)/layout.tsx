/**
 * Layout for the tenant onboarding wizard. Enforces ANALYST/SUPER_ADMIN
 * access at the layout level (in addition to the API route handlers enforcing
 * it independently) so CUSTOMER_VIEWER users are redirected before any
 * onboarding page renders. Defense in depth: the API routes are the real
 * authorization boundary; this is a UX-layer backstop, not a substitute.
 */

import { redirect } from 'next/navigation';
import { ForbiddenError, UnauthenticatedError, requireRole } from '@/lib/auth/rbac';

export default async function OnboardingLayout({ children }: { children: React.ReactNode }) {
  try {
    await requireRole(['ANALYST', 'SUPER_ADMIN']);
  } catch (err) {
    if (err instanceof UnauthenticatedError) {
      redirect('/login');
    }
    if (err instanceof ForbiddenError) {
      redirect('/');
    }
    throw err;
  }

  return (
    <main className="min-h-screen mx-auto max-w-3xl p-8">
      <h1 className="text-xl font-semibold mb-6">Tenant onboarding</h1>
      {children}
    </main>
  );
}
