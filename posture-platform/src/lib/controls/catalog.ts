/**
 * Starter control catalog for M365 / Entra ID security posture monitoring.
 *
 * Each entry is typed against `ControlDefinition` in src/types/domain.ts.
 * `requiredSignals` values are keys on `TenantCollectionResult` in
 * src/types/graph.ts — the scoring engine's evaluators consume exactly those
 * collector outputs to determine a control's ControlStatus.
 *
 * `id` values are stable and must never be reused/repurposed once shipped —
 * ControlResult and Finding rows reference them by string id.
 */

import type { ControlDefinition } from '@/types/domain';

export const CONTROL_CATALOG: ControlDefinition[] = [
  {
    id: 'mfa-all-users-required',
    title: 'Multi-factor authentication required for all users',
    description:
      'All user accounts must be required to complete multi-factor authentication at sign-in, ' +
      'either via a Conditional Access policy targeting All Users with a grant control of ' +
      'requiring MFA, or an equivalent baseline. Prevents account takeover from credential-only ' +
      'compromise (phishing, password spray, credential stuffing).',
    nistFunction: 'PROTECT',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.4' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'mfa-admin-roles-required',
    title: 'Multi-factor authentication required for privileged administrator roles',
    description:
      'Users assigned any highly-privileged directory role (e.g. Global Administrator, ' +
      'Privileged Role Administrator, Security Administrator) must have a Conditional Access ' +
      'policy enforcing MFA scoped to those roles, independent of the all-users baseline, so ' +
      'admin coverage cannot silently regress.',
    nistFunction: 'PROTECT',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(2)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.5' },
    ],
    requiredSignals: ['conditionalAccessPolicies', 'privilegedRoleAssignments'],
  },
  {
    id: 'legacy-authentication-blocked',
    title: 'Legacy authentication protocols blocked',
    description:
      'Basic/legacy authentication protocols (POP, IMAP, SMTP AUTH, older Exchange ActiveSync ' +
      'clients, etc.) that cannot enforce Conditional Access or MFA must be blocked tenant-wide ' +
      'via a Conditional Access policy targeting legacy client apps.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.6' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'ca-compliant-device-admin-access',
    title: 'Conditional Access requires compliant/managed device for admin access',
    description:
      'Administrative role sign-ins must be restricted to devices marked compliant (Intune) or ' +
      'hybrid Azure AD joined via a Conditional Access grant control, reducing exposure from ' +
      'unmanaged or unknown endpoints performing privileged operations.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-19' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.9' },
    ],
    requiredSignals: ['conditionalAccessPolicies', 'privilegedRoleAssignments'],
  },
  {
    id: 'no-standing-privileged-roles',
    title: 'No standing highly-privileged role assignments without time-bound activation',
    description:
      'Highly-privileged directory roles (Global Administrator, Privileged Role Administrator, ' +
      'etc.) should be assigned eligible/just-in-time via PIM rather than permanently active, ' +
      'minimizing the blast radius of a compromised credential.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-6(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.2.1' },
    ],
    requiredSignals: ['privilegedRoleAssignments'],
  },
  {
    id: 'privileged-role-activation-requires-approval',
    title: 'Privileged role activation requires approval',
    description:
      'Eligible assignments for highly-privileged roles must require approval (and ideally ' +
      'justification + time-bound duration) at activation time, so elevation events are ' +
      'reviewable rather than self-service and silent.',
    nistFunction: 'GOVERN',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'GV.PO-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-6(5)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.2.2' },
    ],
    requiredSignals: ['privilegedRoleAssignments'],
  },
  {
    id: 'guest-access-review-configured',
    title: 'Guest user access review configured',
    description:
      'A recurring access review must be configured for guest (B2B) users to periodically ' +
      'validate continued business need, preventing indefinite accumulation of external access.',
    nistFunction: 'IDENTIFY',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'ID.AM-08' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(3)' },
      { framework: 'CIS_M365_V3', controlId: '1.1.2' },
    ],
    requiredSignals: ['conditionalAccessPolicies', 'recentSignIns'],
  },
  {
    id: 'risky-sign-ins-blocked-or-step-up',
    title: 'Risky sign-ins blocked or require step-up authentication',
    description:
      'Sign-ins flagged as medium/high risk by Identity Protection must be blocked or forced ' +
      'through step-up (MFA + secure password change) via risk-based Conditional Access, rather ' +
      'than allowed through unchallenged.',
    nistFunction: 'DETECT',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.CM-09' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(12)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.3.1' },
    ],
    requiredSignals: ['riskyUsers', 'riskDetections', 'conditionalAccessPolicies'],
  },
  {
    id: 'security-defaults-or-ca-baseline-enabled',
    title: 'Security defaults or equivalent Conditional Access baseline enabled',
    description:
      'Tenants must have either Entra ID Security Defaults enabled or a documented Conditional ' +
      'Access baseline of equivalent-or-greater strength (MFA, blocking legacy auth, protecting ' +
      'privileged actions). A tenant with neither has no enforced identity baseline.',
    nistFunction: 'GOVERN',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'GV.PO-01' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-6' },
      { framework: 'CIS_M365_V3', controlId: '5.2.1.1' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'mailbox-forwarding-external-blocked',
    title: 'Automatic mailbox forwarding to external domains blocked',
    description:
      'Exchange Online transport/mail-flow rules or anti-exfiltration policy must block ' +
      'automatic forwarding of mail to external domains, a common data-exfiltration and ' +
      'business-email-compromise persistence technique.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-7' },
      { framework: 'CIS_M365_V3', controlId: '6.2.1' },
    ],
    requiredSignals: ['secureScore'],
  },
  {
    id: 'admin-consent-workflow-required',
    title: 'Admin consent required for application permissions (block user consent to unverified apps)',
    description:
      'User consent to applications requesting permissions must be restricted (ideally disabled ' +
      'entirely for anything beyond low-risk permissions), with an admin consent workflow in ' +
      'place, preventing illicit consent-phishing OAuth apps from gaining tenant access.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.6.1' },
    ],
    requiredSignals: ['secureScore'],
  },
  {
    id: 'audit-log-retention-enabled',
    title: 'Unified audit log retention/ingestion enabled',
    description:
      'The Microsoft 365 unified audit log must be enabled with a retention policy sufficient ' +
      'for incident investigation and compliance requirements, and must be actively ingested by ' +
      'this platform for detection coverage.',
    nistFunction: 'DETECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.AE-02' },
      { framework: 'NIST_800_53_R5', controlId: 'AU-11' },
      { framework: 'CIS_M365_V3', controlId: '3.1.1' },
    ],
    requiredSignals: ['recentSignIns'],
  },
  {
    id: 'break-glass-accounts-excluded-and-monitored',
    title: 'Break-glass accounts excluded from Conditional Access but actively monitored',
    description:
      'At least two dedicated emergency-access ("break-glass") accounts must exist, be excluded ' +
      'from standard Conditional Access policies to guarantee access during an outage, and be ' +
      'monitored so that any sign-in against them triggers immediate alerting.',
    nistFunction: 'RESPOND',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'RS.MA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'CP-2' },
      { framework: 'CIS_M365_V3', controlId: '5.2.4.1' },
    ],
    requiredSignals: ['conditionalAccessPolicies', 'recentSignIns'],
  },
  {
    id: 'inactive-account-review',
    title: 'Inactive/stale account review process in place',
    description:
      'Accounts with no interactive sign-in activity for an extended period (e.g. 90 days) must ' +
      'be identified and reviewed for disablement or removal, reducing the standing attack ' +
      'surface of dormant credentials.',
    nistFunction: 'IDENTIFY',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'ID.AM-08' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(3)' },
      { framework: 'CIS_M365_V3', controlId: '1.1.3' },
    ],
    requiredSignals: ['recentSignIns'],
  },
  {
    id: 'secure-score-above-threshold',
    title: 'Microsoft Secure Score above threshold and trending upward',
    description:
      'Tenant Secure Score (current/max ratio) must remain above an organization-defined ' +
      'threshold and must not show a sustained downward trend across snapshots, acting as a ' +
      'composite signal that complements the discrete controls in this catalog.',
    nistFunction: 'IDENTIFY',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'ID.RA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'RA-3' },
      { framework: 'CIS_M365_V3', controlId: '1.0.0' },
    ],
    requiredSignals: ['secureScore'],
  },
  {
    id: 'high-risk-users-remediated',
    title: 'High-risk users are confirmed remediated or dismissed, not left at-risk',
    description:
      'Users flagged by Identity Protection as high risk must not remain in an "atRisk" state ' +
      'indefinitely; they must be actively investigated and moved to remediated, confirmed safe, ' +
      'or confirmed compromised (with follow-up response) within a defined SLA.',
    nistFunction: 'RESPOND',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'RS.AN-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IR-4' },
      { framework: 'CIS_M365_V3', controlId: '5.2.3.2' },
    ],
    requiredSignals: ['riskyUsers'],
  },
  {
    id: 'privileged-role-assignment-drift-detected',
    title: 'Privileged role assignment changes are detected and reviewed',
    description:
      'New assignments to highly-privileged roles (or role assignments to service principals) ' +
      'must be detectable as a change from the prior collection cycle so unexpected privilege ' +
      'escalation is surfaced quickly rather than discovered during a periodic manual audit.',
    nistFunction: 'DETECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.CM-09' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(4)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.2.3' },
    ],
    requiredSignals: ['privilegedRoleAssignments'],
  },
];
