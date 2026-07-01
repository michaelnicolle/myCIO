/**
 * Core domain contracts shared across the app. These are the stable interfaces
 * that the Graph collectors, scoring engine, persistence layer, and dashboard
 * UI all code against, so each can be built independently.
 */

export type Framework = 'NIST_CSF_2_0' | 'NIST_800_53_R5' | 'CIS_M365_V3';

export type NistFunction = 'GOVERN' | 'IDENTIFY' | 'PROTECT' | 'DETECT' | 'RESPOND' | 'RECOVER';

export type ControlStatus = 'PASS' | 'FAIL' | 'PARTIAL' | 'NOT_APPLICABLE' | 'UNKNOWN';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

/** A single control definition in the catalog (framework-agnostic, mapped to one or more frameworks). */
export interface ControlDefinition {
  /** Stable internal id, e.g. "mfa-all-users-required". Never reuse or repurpose an id. */
  id: string;
  title: string;
  description: string;
  nistFunction: NistFunction;
  mappings: Array<{ framework: Framework; controlId: string }>;
  severity: Severity;
  /** Which collector output this control's evaluator consumes, e.g. "conditionalAccessPolicies". */
  requiredSignals: string[];
}

/** Result of evaluating one control for one tenant at one point in time. */
export interface ControlResult {
  controlId: string;
  tenantId: string;
  status: ControlStatus;
  evaluatedAt: string; // ISO 8601
  detail?: string;
  evidence?: Record<string, unknown>;
}

/** A finding is an actionable, human-facing surfacing of a failed/partial control result. */
export interface Finding {
  id: string;
  tenantId: string;
  controlId: string;
  severity: Severity;
  title: string;
  description: string;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'RISK_ACCEPTED';
  firstDetectedAt: string;
  lastSeenAt: string;
  resolvedAt?: string;
}

/** Aggregate posture snapshot for a tenant at a point in time, used for trend charts. */
export interface PostureSnapshot {
  tenantId: string;
  takenAt: string; // ISO 8601
  overallScore: number; // 0-100
  functionScores: Record<NistFunction, number>;
  secureScore?: { current: number; max: number };
  openFindingsBySeverity: Record<Severity, number>;
}

/** Minimal tenant record the app operates on. Credentials are referenced, never embedded. */
export interface TenantSummary {
  id: string;
  organizationId: string;
  displayName: string;
  entraTenantId: string; // customer's Entra ID (Azure AD) tenant GUID
  status: 'ONBOARDING' | 'ACTIVE' | 'CREDENTIAL_EXPIRED' | 'SUSPENDED';
  onboardedAt: string;
}

/**
 * Least-privilege Microsoft Graph *application* permission scopes this platform requests.
 * Read-only by design; write/remediation scopes are opt-in per tenant and never default-on.
 */
export const REQUIRED_GRAPH_APPLICATION_SCOPES = [
  'SecurityEvents.Read.All',
  'IdentityRiskEvent.Read.All',
  'IdentityRiskyUser.Read.All',
  'AuditLog.Read.All',
  'Policy.Read.All',
  'RoleManagement.Read.Directory',
  'Directory.Read.All',
  'User.Read.All',
  'Reports.Read.All',
] as const;

export type RequiredGraphScope = (typeof REQUIRED_GRAPH_APPLICATION_SCOPES)[number];
