import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getAuthorizedSession } from '@/lib/auth';
import { prisma } from '@/lib/db/client';
import { getSnapshotHistory, getOpenFindings } from '@/lib/trends/query';
import ScoreCard from '@/components/ScoreCard';
import TrendChart from '@/components/TrendChart';
import FindingsTable from '@/components/FindingsTable';
import type { NistFunction } from '@/types/domain';

export const dynamic = 'force-dynamic';

const NIST_FUNCTIONS: NistFunction[] = [
  'GOVERN',
  'IDENTIFY',
  'PROTECT',
  'DETECT',
  'RESPOND',
  'RECOVER',
];

interface TenantDetailPageProps {
  params: { tenantId: string };
}

export default async function TenantDetailPage({ params }: TenantDetailPageProps) {
  const { tenantId } = params;

  const session = await getAuthorizedSession();
  if (!session) {
    return (
      <main className="p-8">
        <p className="text-sm text-gray-600">Not authorized.</p>
      </main>
    );
  }

  // SECURITY: never trust params.tenantId alone. A CUSTOMER_VIEWER (or any
  // role) must only ever see data for tenants owned by their own
  // organization. We verify ownership by looking the tenant up scoped to
  // BOTH tenantId and the session's organizationId — if the tenant belongs
  // to a different organization, this returns null exactly as if the tenant
  // didn't exist, so we 404 rather than leak existence or data.
  const tenant = await prisma.tenant.findFirst({
    where: { id: tenantId, organizationId: session.organizationId },
    select: { id: true, displayName: true, status: true, entraTenantId: true },
  });

  if (!tenant) {
    notFound();
  }

  // Ownership is now confirmed for this session's organization, so it's safe
  // to fetch tenant-scoped data using tenantId directly.
  const [history, openFindings] = await Promise.all([
    getSnapshotHistory(tenantId, 90),
    getOpenFindings(tenantId),
  ]);

  const latest = history.length > 0 ? history[history.length - 1] : undefined;

  return (
    <main className="p-8 space-y-8">
      <div>
        <Link href="/overview" className="text-sm text-indigo-600 hover:underline">
          &larr; Back to overview
        </Link>
        <div className="mt-2 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">{tenant.displayName}</h1>
            <p className="mt-1 text-sm text-gray-600">
              {tenant.status} &middot; Entra tenant {tenant.entraTenantId}
            </p>
          </div>
        </div>
      </div>

      <section>
        <h2 className="text-sm font-medium text-gray-900 mb-3">Posture scores</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-7">
          <ScoreCard label="Overall" score={latest?.overallScore ?? 0} />
          {NIST_FUNCTIONS.map((fn) => (
            <ScoreCard
              key={fn}
              label={fn.charAt(0) + fn.slice(1).toLowerCase()}
              score={latest?.functionScores[fn] ?? 0}
              compact
            />
          ))}
        </div>
      </section>

      <section>
        <TrendChart
          data={history.map((snapshot) => ({
            takenAt: snapshot.takenAt,
            overallScore: snapshot.overallScore,
          }))}
          dataKey="overallScore"
          title="Overall score — last 90 days"
        />
      </section>

      <section>
        <h2 className="text-sm font-medium text-gray-900 mb-3">Open findings</h2>
        <FindingsTable findings={openFindings} caption={`Open findings for ${tenant.displayName}`} />
      </section>
    </main>
  );
}
