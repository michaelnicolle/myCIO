/**
 * SecureScoreBreakdown: ranked table of the current outstanding Microsoft
 * Secure Score per-control gaps for a tenant. This is the "actionable" half
 * of Secure Score — distinct from the trend chart of the aggregate
 * current/max percentage — so an analyst can see specifically which
 * Microsoft-recommended actions (e.g. "AdminMFAV2") would most improve the
 * tenant's score. Server component; caller supplies pre-fetched data so this
 * stays render-only, matching FindingsTable's convention.
 */

import type { SecureScoreControlPoint } from '@/lib/trends/query';

interface SecureScoreBreakdownProps {
  controls: SecureScoreControlPoint[];
  /** Max score a single control can reach; Microsoft does not expose this per-control in our
   * collected shape, so this table ranks by absolute score ascending (lowest-scoring — i.e.
   * least-implemented — controls first) rather than by a normalized "gap", which is the best
   * available proxy for improvement potential without a per-control max. */
  caption?: string;
}

function formatControlName(controlName: string): string {
  // Microsoft's controlName values are compact identifiers (e.g. "AdminMFAV2");
  // show them verbatim (analysts recognize these from the M365 Defender portal)
  // rather than inventing a display title we can't reliably derive.
  return controlName;
}

export default function SecureScoreBreakdown({ controls, caption }: SecureScoreBreakdownProps) {
  if (controls.length === 0) {
    return (
      <div className="rounded-lg border border-gray-200 bg-white p-6 text-center shadow-sm">
        <p className="text-sm text-gray-500">
          No Microsoft Secure Score data collected yet for this tenant.
        </p>
      </div>
    );
  }

  const byCategory = new Map<string, SecureScoreControlPoint[]>();
  for (const control of controls) {
    const list = byCategory.get(control.controlCategory) ?? [];
    list.push(control);
    byCategory.set(control.controlCategory, list);
  }
  const categories = Array.from(byCategory.keys()).sort();

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <thead className="bg-gray-50">
          <tr>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Category
            </th>
            <th scope="col" className="px-4 py-2 text-left font-medium text-gray-600">
              Control
            </th>
            <th scope="col" className="px-4 py-2 text-right font-medium text-gray-600">
              Current score
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {categories.map((category) =>
            (byCategory.get(category) ?? []).map((control, idx) => (
              <tr key={control.controlName} className="hover:bg-gray-50">
                <td className="px-4 py-2 align-top text-gray-700">
                  {idx === 0 ? category : null}
                </td>
                <td className="px-4 py-2 align-top font-mono text-xs text-gray-900">
                  {formatControlName(control.controlName)}
                </td>
                <td className="px-4 py-2 align-top text-right text-gray-700">
                  {control.score.toFixed(2)}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
