/**
 * SecureScoreBadge: a small pill-style indicator for Microsoft Secure Score,
 * used on the fleet-wide Overview page's tenant cards.
 *
 * Deliberately NOT a ScoreCard ring — ScoreCard is reserved for the
 * platform's own NIST-based composite score, and re-using an identical ring
 * for a second, unrelated metric on the same card would make the two easy to
 * confuse at a glance. This renders as a compact labeled pill instead, so
 * "Secure Score" (Microsoft's own metric) is visually distinct from
 * "Overall" (our NIST composite) even when they sit right next to each
 * other on a tenant card.
 */

import { getScoreBand, type ScoreBand } from './ScoreCard';

const BAND_PILL_STYLES: Record<ScoreBand, string> = {
  critical: 'bg-red-50 text-red-700 ring-red-600/20',
  watch: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  healthy: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20',
};

interface SecureScoreBadgeProps {
  /** Microsoft Secure Score numerator, e.g. snapshot.secureScore.current. */
  current?: number;
  /** Microsoft Secure Score denominator, e.g. snapshot.secureScore.max. */
  max?: number;
}

export default function SecureScoreBadge({ current, max }: SecureScoreBadgeProps) {
  const hasData = typeof current === 'number' && typeof max === 'number' && max > 0;

  if (!hasData) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-400 ring-1 ring-inset ring-gray-400/20"
        title="No Microsoft Secure Score data collected yet for this tenant"
      >
        Secure Score: no data
      </span>
    );
  }

  const pct = Math.max(0, Math.min(100, Math.round((current / max) * 100)));
  const band = getScoreBand(pct);

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${BAND_PILL_STYLES[band]}`}
      title={`Microsoft Secure Score: ${current}/${max} (${pct}%)`}
    >
      Secure Score: {pct}%
    </span>
  );
}
