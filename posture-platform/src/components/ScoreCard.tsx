/**
 * ScoreCard: a compact card rendering a 0-100 posture score with a colored
 * progress ring and a label. Reusable for the overall tenant score and for
 * each individual NIST CSF 2.0 function score (GOVERN/IDENTIFY/PROTECT/
 * DETECT/RESPOND/RECOVER).
 */

export type ScoreBand = 'critical' | 'watch' | 'healthy';

export function getScoreBand(score: number): ScoreBand {
  if (score < 50) return 'critical';
  if (score < 80) return 'watch';
  return 'healthy';
}

const BAND_STYLES: Record<ScoreBand, { ring: string; text: string; track: string }> = {
  critical: { ring: 'stroke-red-500', text: 'text-red-600', track: 'stroke-red-100' },
  watch: { ring: 'stroke-amber-500', text: 'text-amber-600', track: 'stroke-amber-100' },
  healthy: { ring: 'stroke-emerald-500', text: 'text-emerald-600', track: 'stroke-emerald-100' },
};

interface ScoreCardProps {
  /** Card heading, e.g. "Overall Posture" or a NIST function name. */
  label: string;
  /** Score from 0-100. Values outside this range are clamped. */
  score: number;
  /** Optional smaller caption under the label, e.g. "Last updated Jul 1". */
  caption?: string;
  /** Render more compactly for grid layouts with many function cards. */
  compact?: boolean;
}

const RADIUS = 36;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export default function ScoreCard({ label, score, caption, compact = false }: ScoreCardProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const band = getScoreBand(clamped);
  const styles = BAND_STYLES[band];
  const dashOffset = CIRCUMFERENCE * (1 - clamped / 100);
  const size = compact ? 88 : 120;
  const viewBox = 96;

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          viewBox={`0 0 ${viewBox} ${viewBox}`}
          width={size}
          height={size}
          className="-rotate-90"
          role="img"
          aria-label={`${label} score: ${clamped} out of 100`}
        >
          <circle
            cx={viewBox / 2}
            cy={viewBox / 2}
            r={RADIUS}
            fill="none"
            strokeWidth={8}
            className={styles.track}
          />
          <circle
            cx={viewBox / 2}
            cy={viewBox / 2}
            r={RADIUS}
            fill="none"
            strokeWidth={8}
            strokeLinecap="round"
            className={styles.ring}
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={dashOffset}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-xl font-semibold ${styles.text}`}>{clamped}</span>
          <span className="text-[10px] text-gray-400">/100</span>
        </div>
      </div>
      <div className="text-center">
        <p className="text-sm font-medium text-gray-900">{label}</p>
        {caption ? <p className="text-xs text-gray-500">{caption}</p> : null}
      </div>
    </div>
  );
}
