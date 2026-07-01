/**
 * FindingsTable: accessible tabular listing of open findings for a tenant.
 * Server component — no client-side interactivity required for the base
 * table; sorting is a nice-to-have omitted here to keep this simple and
 * server-rendered (caller can pre-sort the array before passing it in).
 */

import type { Finding } from '@/types/domain';
import { SeverityBadge } from '@/components/SeverityBadge';

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFORMATIONAL: 4,
};

interface FindingsTableProps {
  findings: Finding[];
  /** Sort by severity (critical first) before rendering. Defaults to true. */
  sortBySeverity?: boolean;
  caption?: string;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function FindingsTable({
  findings,
  sortBySeverity = true,
  caption,
}: FindingsTableProps) {
  const rows = sortBySeverity
    ? [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    : findings;

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-gray-200 bg-white p-6 text-center shadow-sm">
        <p className="text-sm text-gray-500">No open findings. This tenant is in good standing.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead className="bg-gray-50">
          <tr>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Severity
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Finding
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Control
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Status
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              First detected
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Last seen
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {rows.map((finding) => (
            <tr key={finding.id} className="hover:bg-gray-50">
              <td className="px-4 py-2 align-top">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="px-4 py-2 align-top">
                <p className="font-medium text-gray-900">{finding.title}</p>
                <p className="text-xs text-gray-500">{finding.description}</p>
              </td>
              <td className="px-4 py-2 align-top font-mono text-xs text-gray-600">
                {finding.controlId}
              </td>
              <td className="px-4 py-2 align-top text-gray-700">{finding.status}</td>
              <td className="px-4 py-2 align-top text-gray-700">
                {formatDate(finding.firstDetectedAt)}
              </td>
              <td className="px-4 py-2 align-top text-gray-700">
                {formatDate(finding.lastSeenAt)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
