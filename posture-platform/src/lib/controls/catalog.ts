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
      'business-email-compromise persistence technique. ' +
      'NOTE: this control now has a direct evaluator backed by the authoritative ' +
      '`exoTeams.exoCompliance.remoteDomains`/`transportRules` PowerShell signals (see ' +
      'src/lib/scoring/evaluators.ts), superseding the original plan to infer this indirectly ' +
      'from Secure Score control-improvement-action data; `requiredSignals` below has been ' +
      'updated to reflect the direct signals actually consumed.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-7' },
      { framework: 'CIS_M365_V3', controlId: '6.2.1' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.remoteDomains', 'exoTeams.exoCompliance.transportRules'],
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

  // ---------------------------------------------------------------------------
  // New controls informed by CISA ScubaGear / Maester / Prowler / EIDSCA checks.
  // Appended below without renumbering/reordering the 17 existing controls above.
  // ---------------------------------------------------------------------------

  {
    id: 'weak-authentication-methods-disabled',
    title: 'Weak (phishable) authentication methods disabled tenant-wide',
    description:
      'SMS, Voice Call, and Email One-Time-Passcode authentication methods must be disabled in ' +
      'the tenant-wide Authentication Methods Policy. These methods are phishable and vulnerable ' +
      'to SIM-swapping and should not be available as an MFA or self-service-password-reset factor.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.1' },
    ],
    requiredSignals: ['authenticationMethodsPolicy'],
  },
  {
    id: 'authenticator-number-matching-required',
    title: 'Microsoft Authenticator push requires number matching',
    description:
      'The Microsoft Authenticator method configuration must require number matching on push ' +
      'notification approvals, closing off MFA-fatigue ("push bombing") attacks where a user ' +
      'accidentally approves an attacker-initiated sign-in.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.2' },
    ],
    requiredSignals: ['authenticationMethodsPolicy'],
  },
  {
    id: 'fido2-attestation-enforced',
    title: 'FIDO2 security key attestation enforced when FIDO2 is enabled',
    description:
      'If FIDO2 security keys are enabled as an authentication method, the Authentication Methods ' +
      'Policy must require key attestation so that only authenticator models the organization has ' +
      'vetted can be registered, rather than any FIDO2-compliant device.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
    ],
    requiredSignals: ['authenticationMethodsPolicy'],
  },
  {
    id: 'phishing-resistant-mfa-required',
    title: 'Phishing-resistant MFA (authentication strength) required for broad user scope',
    description:
      'At least one enabled Conditional Access policy must require a phishing-resistant ' +
      'authentication strength (FIDO2, Windows Hello for Business, certificate-based auth) via ' +
      'grantControls.authenticationStrength for all/broad user scope. Stronger than generic MFA, ' +
      'which remains vulnerable to real-time phishing/adversary-in-the-middle relay attacks.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.4' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'device-code-flow-blocked',
    title: 'OAuth device-code authentication flow blocked',
    description:
      'The OAuth 2.0 device-code authorization flow must be blocked tenant-wide via Conditional ' +
      'Access unless explicitly required for specific managed devices (e.g. shared/kiosk ' +
      'hardware), since it is a common technique used to bypass Conditional Access/MFA in ' +
      'phishing campaigns targeting Entra ID.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.7' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'managed-device-required-for-mfa-registration',
    title: 'Managed/compliant device required to register security information',
    description:
      'Registering new MFA/security-info methods must be restricted to compliant or hybrid-joined ' +
      'devices via a Conditional Access policy scoped to the "register security information" user ' +
      'action, preventing an attacker with only a stolen password from enrolling their own MFA ' +
      'method from an unmanaged device.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-19' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.8' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'high-risk-users-blocked-by-ca',
    title: 'Conditional Access blocks sign-in for high user-risk',
    description:
      'At least one enabled Conditional Access policy must block sign-in outright for users ' +
      'Identity Protection has scored at "high" risk, rather than only requiring step-up, ' +
      'proactively containing accounts most likely already compromised.',
    nistFunction: 'PROTECT',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(12)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.3.1' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'high-risk-signins-blocked-by-ca',
    title: 'Conditional Access blocks sign-in for high sign-in-risk',
    description:
      'At least one enabled Conditional Access policy must block sign-in when the session-level ' +
      '(sign-in) risk is scored "high" by Identity Protection, addressing risk detected at the ' +
      'individual authentication event rather than the longer-lived user risk score.',
    nistFunction: 'PROTECT',
    severity: 'CRITICAL',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(12)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.3.3' },
    ],
    requiredSignals: ['conditionalAccessPolicies'],
  },
  {
    id: 'global-admin-count-in-range',
    title: 'Global Administrator count within a safe range (2-8)',
    description:
      'The tenant should have between 2 and 8 active (permanent) Global Administrator role ' +
      'assignments: fewer than 2 creates a bus-factor/lockout risk with no redundancy, while more ' +
      'than 8 unnecessarily broadens the blast radius of a single compromised admin credential.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-6(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.1' },
    ],
    requiredSignals: ['privilegedRoleAssignments'],
  },
  {
    id: 'user-app-registration-restricted',
    title: 'Only admins can register new application registrations',
    description:
      'The default user role permissions must disable non-admin users\' ability to register new ' +
      'application registrations in Entra ID, preventing unreviewed/unmanaged app registrations ' +
      'from becoming an OAuth-consent-phishing or persistence vector.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.6.2' },
    ],
    requiredSignals: ['authorizationPolicy'],
  },
  {
    id: 'user-consent-to-apps-restricted',
    title: 'Regular users cannot grant consent to application permissions themselves',
    description:
      'The default user role permissions must not leave a broad, unrestricted user-consent policy ' +
      'assigned, so that granting an application permissions to tenant data requires an admin (or ' +
      'a tightly scoped admin-reviewed policy) rather than any end user clicking "Accept" on an ' +
      'OAuth consent-phishing prompt.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.6.1' },
    ],
    requiredSignals: ['authorizationPolicy'],
  },
  {
    id: 'guest-user-restricted-role',
    title: 'Guest users are assigned the most-restricted guest role',
    description:
      'The tenant-wide default guest user role must be set to the most-restrictive built-in guest ' +
      'role (limited to their own object properties), rather than granting guests the same ' +
      'directory-object visibility as members.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-6' },
      { framework: 'CIS_M365_V3', controlId: '1.2.1' },
    ],
    requiredSignals: ['authorizationPolicy'],
  },
  {
    id: 'guest-invites-restricted-to-admins',
    title: 'Guest invitations restricted to admins/designated inviters',
    description:
      'The tenant-wide "who can invite guests" setting must be restricted to admins and users ' +
      'explicitly granted the guest-inviter role, not left open to all members or everyone, so ' +
      'external access grants go through an accountable party.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '1.2.2' },
    ],
    requiredSignals: ['authorizationPolicy'],
  },
  {
    id: 'password-never-expires-policy',
    title: 'Verified domains use a never-expiring password policy',
    description:
      'Verified managed domains should configure passwords to never expire (per NIST 800-63B and ' +
      'OMB M-22-09 guidance against forced periodic rotation, which drives predictable password ' +
      'patterns), relying instead on MFA, risk-based sign-in, and breach-triggered resets.',
    nistFunction: 'PROTECT',
    severity: 'LOW',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-03' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-5(1)' },
      { framework: 'CIS_M365_V3', controlId: '1.3.1' },
    ],
    requiredSignals: ['domains'],
  },
  {
    id: 'app-registration-credential-hygiene',
    title: 'Application registrations use bounded-lifetime, certificate-preferred credentials',
    description:
      'App registrations should prefer certificate credentials over client secrets, and any ' +
      'credential in use should have a bounded lifetime (client secrets no longer than 180 days, ' +
      'certificates no longer than 365 days), limiting the exposure window of a leaked long-lived ' +
      'secret.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-5(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.1.7' },
    ],
    requiredSignals: ['applications'],
  },
  {
    id: 'privileged-service-principal-no-owners',
    title: 'Privileged service principals have zero owners',
    description:
      'Service principals holding a permanent privileged directory role must have zero assigned ' +
      'owners; any owner can rotate the service principal\'s credentials and thereby inherit its ' +
      'privileged role entirely outside of any approval workflow.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-6(1)' },
    ],
    requiredSignals: ['privilegedServicePrincipals'],
  },
  {
    id: 'privileged-service-principal-no-client-secrets',
    title: 'Privileged service principals use no client secrets',
    description:
      'Service principals holding a permanent privileged directory role should authenticate via ' +
      'certificate credentials or managed identity rather than client secrets, reducing the risk ' +
      'of a leaked long-lived shared secret granting privileged directory access.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-5(1)' },
    ],
    requiredSignals: ['privilegedServicePrincipals'],
  },
  {
    id: 'non-privileged-users-mfa-registered',
    title: 'Non-privileged users have an MFA method registered',
    description:
      'Nearly all non-admin user accounts should have at least one MFA method registered, ' +
      'independent of whether a Conditional Access policy currently enforces its use, so that ' +
      'enforcement can be tightened without a wave of users being locked out for lack of an ' +
      'enrolled factor.',
    nistFunction: 'IDENTIFY',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'ID.RA-01' },
      { framework: 'NIST_800_53_R5', controlId: 'IA-2(1)' },
      { framework: 'CIS_M365_V3', controlId: '5.2.2.3' },
    ],
    requiredSignals: ['userRegistrationDetails'],
  },

  // ---------------------------------------------------------------------------
  // Exchange Online / Security & Compliance / Microsoft Teams controls, sourced
  // from the PowerShell-collected signals in src/types/exoTeams.ts (nested at
  // TenantCollectionResult.exoTeams.{exoCompliance,teams}). Appended below
  // without reordering the 35 existing controls above. requiredSignals here use
  // a dot-path convention (e.g. 'exoTeams.exoCompliance.dkimConfigs') since these
  // signals are nested rather than flat top-level TenantCollectionResult keys —
  // requiredSignals is documentation/UI-facing (see evaluators.ts), not a literal
  // key lookup, so this remains consistent with its existing usage.
  // ---------------------------------------------------------------------------

  {
    id: 'dkim-signing-enabled-all-domains',
    title: 'DKIM signing enabled for all accepted domains',
    description:
      'DomainKeys Identified Mail (DKIM) signing must be enabled for every accepted domain in ' +
      'Exchange Online, allowing receiving mail systems to cryptographically verify mail was not ' +
      'altered in transit and was sent from an authorized source, and underpinning DMARC alignment.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-8' },
      { framework: 'CIS_M365_V3', controlId: '2.1.9' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.dkimConfigs'],
  },
  {
    id: 'dmarc-policy-reject',
    title: 'DMARC policy set to reject for all domains',
    description:
      'Every domain must publish a DMARC record with a policy of "p=reject", instructing ' +
      'receiving mail systems to reject mail failing SPF/DKIM alignment outright rather than ' +
      'merely flagging or quarantining it, closing off domain-spoofing phishing/BEC campaigns.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-8' },
      { framework: 'CIS_M365_V3', controlId: '2.1.10' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.dmarcConfigs'],
  },
  {
    id: 'smtp-auth-disabled-tenant-wide',
    title: 'Legacy SMTP AUTH disabled tenant-wide',
    description:
      'Legacy basic authentication for SMTP (client submission) must be disabled tenant-wide in ' +
      'the Exchange Online organization configuration, since it cannot enforce Conditional Access ' +
      'or MFA and is a common target for password-spray campaigns against mailboxes.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'CM-7' },
      { framework: 'CIS_M365_V3', controlId: '6.5.3' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.organizationMailConfig'],
  },
  {
    id: 'mailbox-auditing-not-bypassed',
    title: 'No mailboxes have audit-bypass enabled',
    description:
      'No mailbox should have per-mailbox audit-bypass enabled, since a bypass entry silently ' +
      'suppresses audit record generation for that mailbox even while tenant-wide mailbox auditing ' +
      'is otherwise on, creating an investigative blind spot that is easy to overlook.',
    nistFunction: 'DETECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.AE-02' },
      { framework: 'NIST_800_53_R5', controlId: 'AU-12' },
      { framework: 'CIS_M365_V3', controlId: '3.1.2' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.mailboxAuditBypass'],
  },
  {
    id: 'mailbox-auditing-enabled-tenant-wide',
    title: 'Tenant-wide mailbox auditing enabled',
    description:
      'Per-mailbox Exchange audit logging (distinct from the Unified Audit Log) must not be ' +
      'disabled at the organization level, ensuring mailbox-level actions (access, sends, folder ' +
      'permission changes) remain recorded for investigation.',
    nistFunction: 'DETECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.AE-02' },
      { framework: 'NIST_800_53_R5', controlId: 'AU-12' },
      { framework: 'CIS_M365_V3', controlId: '3.1.2' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.organizationMailConfig'],
  },
  {
    id: 'transport-rules-no-external-forwarding',
    title: 'No transport rules auto-forward or BCC mail externally',
    description:
      'No enabled Exchange Online mail-flow (transport) rule should automatically forward or BCC ' +
      'messages to an external recipient, a common data-exfiltration and business-email-compromise ' +
      'persistence technique used after an initial mailbox compromise.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-7' },
      { framework: 'CIS_M365_V3', controlId: '6.2.1' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.transportRules'],
  },
  {
    id: 'remote-domain-auto-forward-disabled',
    title: 'Remote domains do not allow automatic forwarding',
    description:
      'Remote domain configurations (especially the default "*" remote domain) must not have ' +
      'automatic forwarding enabled, preventing mailboxes from silently auto-forwarding mail to ' +
      'external addresses outside of the reviewed transport-rule/anti-exfiltration path.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-02' },
      { framework: 'NIST_800_53_R5', controlId: 'SC-7' },
      { framework: 'CIS_M365_V3', controlId: '6.2.2' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.remoteDomains'],
  },
  {
    id: 'calendar-sharing-not-external',
    title: 'Calendar sharing policies do not expose details externally',
    description:
      'Sharing policies must not share calendar free/busy or detailed availability information ' +
      'with all external domains or anonymous users, limiting reconnaissance value available to ' +
      'an external party from calendar metadata alone.',
    nistFunction: 'PROTECT',
    severity: 'LOW',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.DS-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-21' },
      { framework: 'CIS_M365_V3', controlId: '6.5.2' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.sharingPolicies'],
  },
  {
    id: 'spam-filter-policy-active',
    title: 'At least one active hosted content (spam) filter policy',
    description:
      'At least one hosted content filter (anti-spam) policy must be active and not effectively ' +
      'disabled, ensuring inbound mail receives baseline spam-scoring and filtering action rather ' +
      'than passing through unfiltered.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'SI-8' },
      { framework: 'CIS_M365_V3', controlId: '2.1.1' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.hostedContentFilterPolicies'],
  },
  {
    id: 'no-connection-filter-ip-allowlist',
    title: 'Connection filter policy has no IP allow-list entries',
    description:
      'The hosted connection filter policy should not contain entries in its IP allow-list, since ' +
      'allow-listed source IPs bypass spam filtering entirely — a frequently over-permissive ' +
      'misconfiguration that can be abused if any listed sender IP is later compromised or spoofed.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'SI-8' },
      { framework: 'CIS_M365_V3', controlId: '2.1.2' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.hostedConnectionFilterPolicies'],
  },
  {
    id: 'anti-phishing-policy-hardened',
    title: 'Anti-phish policy has mailbox/spoof intelligence and targeted user protection enabled',
    description:
      'The default anti-phish policy must have mailbox intelligence, spoof intelligence, and ' +
      'targeted user protection all enabled, providing layered detection of impersonation and ' +
      'spoofing attacks beyond basic spam/malware filtering.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'SI-8' },
      { framework: 'CIS_M365_V3', controlId: '2.1.3' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.antiPhishPolicies'],
  },
  {
    id: 'safe-attachments-enabled',
    title: 'Safe Attachments policy enabled with a blocking action',
    description:
      'A Safe Attachments (Defender for Office 365) policy must be enabled with an action that ' +
      'blocks delivery of detected malicious attachments, rather than only monitoring or allowing ' +
      'them through with a warning.',
    nistFunction: 'PROTECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'SI-3' },
      { framework: 'CIS_M365_V3', controlId: '2.1.4' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.safeAttachmentsPolicies'],
  },
  {
    id: 'safe-links-enabled-all-surfaces',
    title: 'Safe Links enabled for Email, Teams, and Office apps',
    description:
      'Safe Links (Defender for Office 365) must be enabled across all three surfaces — Email, ' +
      'Microsoft Teams, and Office apps — rather than only protecting one channel while leaving ' +
      'malicious-link click-time protection off elsewhere.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.PS-01' },
      { framework: 'NIST_800_53_R5', controlId: 'SI-3' },
      { framework: 'CIS_M365_V3', controlId: '2.1.5' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.safeLinksPolicies'],
  },
  {
    id: 'unified-audit-log-ingestion-verified',
    title: 'Unified Audit Log ingestion directly verified as enabled',
    description:
      'The Microsoft 365 Unified Audit Log must be directly verified as ingesting events (via the ' +
      'Security & Compliance PowerShell admin audit log config), rather than inferred indirectly ' +
      'from the presence of Entra ID sign-in log records, which only corroborates that sign-ins are ' +
      'occurring — not that unified audit ingestion itself is on.',
    nistFunction: 'DETECT',
    severity: 'HIGH',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'DE.AE-02' },
      { framework: 'NIST_800_53_R5', controlId: 'AU-11' },
      { framework: 'CIS_M365_V3', controlId: '3.1.1' },
    ],
    requiredSignals: ['exoTeams.exoCompliance.unifiedAuditLogConfig'],
  },
  {
    id: 'teams-external-federation-restricted',
    title: 'Microsoft Teams external federation restricted',
    description:
      'Microsoft Teams external federation (communication with users in other Microsoft 365 ' +
      'tenants) must either be disabled outright, or enabled only with a restricted allow-list of ' +
      'specific external domains rather than left unrestricted to federate with any domain.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-4' },
      { framework: 'CIS_M365_V3', controlId: '8.5.1' },
    ],
    requiredSignals: ['exoTeams.teams.federationConfig'],
  },
  {
    id: 'teams-anonymous-meeting-join-restricted',
    title: 'Anonymous users cannot join or start Teams meetings by default',
    description:
      'The Global (default) Teams meeting policy must not allow anonymous users to join or start ' +
      'meetings, preventing unauthenticated external parties from entering meetings absent an ' +
      'explicit, deliberate per-meeting decision to allow it.',
    nistFunction: 'PROTECT',
    severity: 'MEDIUM',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'PR.AA-05' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-3' },
      { framework: 'CIS_M365_V3', controlId: '8.1.1' },
    ],
    requiredSignals: ['exoTeams.teams.meetingPolicies'],
  },
  {
    id: 'teams-meeting-recording-governed',
    title: 'Teams cloud meeting recording is a deliberate policy decision',
    description:
      'Cloud recording of Teams meetings on the Global meeting policy should reflect a deliberate, ' +
      'reviewed data-handling decision rather than an unreviewed default; recording captures ' +
      'potentially sensitive discussion content and its retention/access should be governed. ' +
      'Judgment call: enabled recording is not inherently insecure, so this is scored as a review ' +
      'flag rather than an outright failure.',
    nistFunction: 'GOVERN',
    severity: 'LOW',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'GV.PO-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AU-11' },
      { framework: 'CIS_M365_V3', controlId: '8.1.2' },
    ],
    requiredSignals: ['exoTeams.teams.meetingPolicies'],
  },
  {
    id: 'teams-external-access-restricted',
    title: 'Teams external access and guest access are deliberately configured',
    description:
      'Teams external access (federation-adjacent contact/1:1-communication with users in other ' +
      'tenants) and guest access should reflect a deliberate configuration matched to the ' +
      'organization\'s collaboration needs rather than being left wide open by default. Judgment ' +
      'call: both are legitimate business features, not inherently misconfigurations, so enabled ' +
      'values are scored as a review flag rather than an outright failure.',
    nistFunction: 'GOVERN',
    severity: 'LOW',
    mappings: [
      { framework: 'NIST_CSF_2_0', controlId: 'GV.PO-01' },
      { framework: 'NIST_800_53_R5', controlId: 'AC-20' },
      { framework: 'CIS_M365_V3', controlId: '8.5.2' },
    ],
    requiredSignals: ['exoTeams.teams.clientConfig'],
  },
];
