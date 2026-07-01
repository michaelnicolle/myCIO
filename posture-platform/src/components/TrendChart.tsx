'use client';

/**
 * TrendChart: an area/line chart of a numeric score over time. Generic over
 * the data point shape so it can render overall score history or a single
 * NIST function's score history — caller picks which numeric field to plot
 * via `dataKey`.
 */

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

interface TrendPoint {
  takenAt: string;
  [key: string]: string | number;
}

interface TrendChartProps<T extends TrendPoint> {
  data: T[];
  /** Which numeric field on each point to plot, e.g. "overallScore". */
  dataKey: keyof T & string;
  /** Chart title shown above the plot area. */
  title?: string;
  /** Line/fill color. Defaults to a neutral indigo. */
  color?: string;
  /** Fixed y-axis domain; scores are 0-100 by default. */
  domain?: [number, number];
  height?: number;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export default function TrendChart<T extends TrendPoint>({
  data,
  dataKey,
  title,
  color = '#4f46e5',
  domain = [0, 100],
  height = 240,
}: TrendChartProps<T>) {
  if (data.length === 0) {
    return (
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        {title ? <h3 className="text-sm font-medium text-gray-900 mb-2">{title}</h3> : null}
        <p className="text-sm text-gray-500">Not enough history to plot a trend yet.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
      {title ? <h3 className="text-sm font-medium text-gray-900 mb-2">{title}</h3> : null}
      <div style={{ width: '100%', height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
            <defs>
              <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis
              dataKey="takenAt"
              tickFormatter={formatDate}
              tick={{ fontSize: 12, fill: '#6b7280' }}
              stroke="#d1d5db"
            />
            <YAxis
              domain={domain}
              tick={{ fontSize: 12, fill: '#6b7280' }}
              stroke="#d1d5db"
              width={36}
            />
            <Tooltip
              labelFormatter={(label: string) => formatDate(label)}
              formatter={(value: number) => [value, 'Score']}
              contentStyle={{ fontSize: 12, borderRadius: 8 }}
            />
            <Area
              type="monotone"
              dataKey={dataKey}
              stroke={color}
              strokeWidth={2}
              fill="url(#trendFill)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
