import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getAuthorizedSession, canAccessTenant } from '@/lib/auth';
import { prisma } from '@/lib/db/client';
import { getSnapshotHistory, getOpenFindings, getLatestSecureScoreControls } from '@/lib/trends/query';
import ScoreCard from '@/components/ScoreCard';
import TrendChart from '@/components/TrendChart';
import FindingsTable from '@/components/FindingsTable';
import SecureScoreBreakdown from '@/components/SecureScoreBreakdown';
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

  // Organization ownership is confirmed, but that alone is not sufficient for
  // CUSTOMER_VIEWER: an Organization (the MSP) can own many unrelated
  // customers' Tenant rows, so a customer's viewer account must additionally
  // be granted explicit access to THIS tenant (see TenantAccess in
  // prisma/schema.prisma). SUPER_ADMIN/ANALYST are unaffected. 404 rather
  // than 403 so this never confirms the tenant's existence to a caller
  // without access.
  if (!(await canAccessTenant(session, tenant.id))) {
    notFound();
  }

  // Ownership and per-tenant access are now confirmed, so it's safe to fetch
  // tenant-scoped data using tenantId directly.
  const [history, openFindings, latestSecureScoreControls] = await Promise.all([
    getSnapshotHistory(tenantId, 90),
    getOpenFindings(tenantId),
    getLatestSecureScoreControls(tenantId),
  ]);

  const latest = history.length > 0 ? history[history.length - 1] : undefined;

  // Secure Score percentage history for the trend chart — only snapshots that
  // actually captured a Secure Score contribute a point (max could theoretically
  // be 0 for a fresh tenant with nothing scored yet; guard against divide-by-zero).
  const secureScoreHistory = history
    .filter((snapshot) => snapshot.secureScore && snapshot.secureScore.max > 0)
    .map((snapshot) => ({
      takenAt: snapshot.takenAt,
      secureScorePct: Math.round((snapshot.secureScore!.current / snapshot.secureScore!.max) * 100),
    }));

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
        <h2 className="text-sm font-medium text-gray-900 mb-3">
          Microsoft Secure Score
        </h2>
        <p className="text-xs text-gray-500 mb-3">
          Microsoft&apos;s own security posture score for this tenant, separate from the NIST-based
          composite score above. Shown as current/max percentage over time, plus the specific
          outstanding controls Microsoft recommends addressing.
        </p>
        <div className="space-y-4">
          <TrendChart
            data={secureScoreHistory}
            dataKey="secureScorePct"
            title="Secure Score — last 90 days"
          />
          <SecureScoreBreakdown
            controls={latestSecureScoreControls}
            caption={`Outstanding Secure Score controls for ${tenant.displayName}`}
          />
        </div>
      </section>

      <section>
        <h2 className="text-sm font-medium text-gray-900 mb-3">Open findings</h2>
        <FindingsTable findings={openFindings} caption={`Open findings for ${tenant.displayName}`} />
      </section>
    </main>
  );
}
