/**
 * Small colored badges for Finding severity and control evaluation status.
 * Kept in a single file since both are tiny, static color-mapping components
 * used side-by-side in FindingsTable.
 */

import type { ControlStatus, Severity } from '@/types/domain';

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-red-100 text-red-800 ring-red-600/20',
  HIGH: 'bg-orange-100 text-orange-800 ring-orange-600/20',
  MEDIUM: 'bg-yellow-100 text-yellow-800 ring-yellow-600/20',
  LOW: 'bg-blue-100 text-blue-800 ring-blue-600/20',
  INFORMATIONAL: 'bg-gray-100 text-gray-700 ring-gray-500/20',
};

const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFORMATIONAL: 'Info',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${SEVERITY_STYLES[severity]}`}
    >
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

const CONTROL_STATUS_STYLES: Record<ControlStatus, string> = {
  PASS: 'bg-emerald-100 text-emerald-800 ring-emerald-600/20',
  FAIL: 'bg-red-100 text-red-800 ring-red-600/20',
  PARTIAL: 'bg-amber-100 text-amber-800 ring-amber-600/20',
  NOT_APPLICABLE: 'bg-gray-100 text-gray-600 ring-gray-500/20',
  UNKNOWN: 'bg-slate-100 text-slate-600 ring-slate-500/20',
};

const CONTROL_STATUS_LABELS: Record<ControlStatus, string> = {
  PASS: 'Pass',
  FAIL: 'Fail',
  PARTIAL: 'Partial',
  NOT_APPLICABLE: 'N/A',
  UNKNOWN: 'Unknown',
};

export function ControlStatusBadge({ status }: { status: ControlStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${CONTROL_STATUS_STYLES[status]}`}
    >
      {CONTROL_STATUS_LABELS[status]}
    </span>
  );
}

export default SeverityBadge;
