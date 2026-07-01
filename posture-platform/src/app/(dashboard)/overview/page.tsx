import Link from 'next/link';
import { getAuthorizedSession, getAccessibleTenantIds } from '@/lib/auth';
import { getLatestSnapshot } from '@/lib/trends/query';
import { prisma } from '@/lib/db/client';
import ScoreCard from '@/components/ScoreCard';
import { SeverityBadge } from '@/components/SeverityBadge';
import type { PostureSnapshot } from '@/types/domain';

export const dynamic = 'force-dynamic';

interface TenantRow {
  id: string;
  displayName: string;
  status: string;
  snapshot: PostureSnapshot | null;
}

async function loadTenantRows(organizationId: string, accessibleTenantIds: 'ALL' | string[]): Promise<TenantRow[]> {
  // Scoped strictly to the caller's organization — never list tenants across
  // organizations. For CUSTOMER_VIEWER sessions, additionally restrict to the
  // specific tenant(s) they've been granted access to: an Organization (the
  // MSP) can own many unrelated customers' Tenant rows, so organizationId
  // scoping alone is not sufficient isolation for that role.
  if (accessibleTenantIds !== 'ALL' && accessibleTenantIds.length === 0) {
    return [];
  }
  const tenants = await prisma.tenant.findMany({
    where: {
      organizationId,
      ...(accessibleTenantIds === 'ALL' ? {} : { id: { in: accessibleTenantIds } }),
    },
    orderBy: { displayName: 'asc' },
    select: { id: true, displayName: true, status: true },
  });

  return Promise.all(
    tenants.map(async (tenant) => ({
      ...tenant,
      snapshot: await getLatestSnapshot(tenant.id),
    })),
  );
}

function criticalHighCount(snapshot: PostureSnapshot | null): number {
  if (!snapshot) return 0;
  return (
    (snapshot.openFindingsBySeverity.CRITICAL ?? 0) + (snapshot.openFindingsBySeverity.HIGH ?? 0)
  );
}

export default async function OverviewPage() {
  const session = await getAuthorizedSession();

  if (!session) {
    return (
      <main className="p-8">
        <p className="text-sm text-gray-600">Not authorized.</p>
      </main>
    );
  }

  const accessibleTenantIds = await getAccessibleTenantIds(session);
  const tenants = await loadTenantRows(session.organizationId, accessibleTenantIds);

  return (
    <main className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Overview</h1>
          <p className="mt-1 text-sm text-gray-600">
            Security posture across all managed customer tenants.
          </p>
        </div>
        <Link
          href="/onboarding"
          className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Onboard a tenant
        </Link>
      </div>

      {tenants.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 bg-white p-12 text-center">
          <h2 className="text-lg font-medium text-gray-900">No tenants onboarded yet</h2>
          <p className="mt-2 text-sm text-gray-600">
            Connect your first customer Microsoft 365 tenant to start tracking its security
            posture and NIST compliance trends.
          </p>
          <Link
            href="/onboarding"
            className="mt-4 inline-flex items-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            Start onboarding
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {tenants.map((tenant) => {
            const criticalHigh = criticalHighCount(tenant.snapshot);
            return (
              <Link
                key={tenant.id}
                href={`/tenants/${tenant.id}`}
                className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm hover:shadow-md hover:border-gray-300 transition"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="truncate text-sm font-semibold text-gray-900">
                      {tenant.displayName}
                    </h2>
                    <p className="mt-0.5 text-xs text-gray-500">{tenant.status}</p>
                  </div>
                  {criticalHigh > 0 ? <SeverityBadge severity="CRITICAL" /> : null}
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <ScoreCard
                    label="Overall"
                    score={tenant.snapshot?.overallScore ?? 0}
                    compact
                  />
                  <div className="text-right text-xs text-gray-600">
                    <p>
                      <span className="font-semibold text-gray-900">{criticalHigh}</span> open
                      critical/high
                    </p>
                    {!tenant.snapshot ? (
                      <p className="mt-1 text-gray-400">No posture data yet</p>
                    ) : null}
                  </div>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </main>
  );
}
