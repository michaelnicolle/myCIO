/**
 * Pure evaluator functions: each inspects a `TenantCollectionResult` and
 * produces a status (plus human-readable detail / machine-readable evidence)
 * for one control in the catalog.
 *
 * Hard rule: if a control's required signal(s) are missing from the
 * collection result (undefined, empty where emptiness is ambiguous-with-not-
 * collected, or explicitly reported as failed in `signals.errors`), the
 * evaluator MUST return UNKNOWN with a detail explaining what's missing.
 * Never infer PASS/FAIL from absent data.
 */

import type {
  TenantCollectionResult,
  GraphConditionalAccessPolicy,
  GraphAuthenticationMethodsPolicy,
} from '@/types/graph';
import type {
  ExoComplianceCollectionResult,
  TeamsCollectionResult,
} from '@/types/exoTeams';
import type { ControlStatus } from '@/types/domain';

/**
 * Well-known Global Administrator directory role template id (stable across all tenants).
 * Mirrors the same GUID used in `PRIVILEGED_ROLE_TEMPLATE_IDS` in src/lib/graph/collectors.ts
 * (see that file's comment block for the Microsoft documentation reference). Duplicated here
 * as a local literal — rather than importing from collectors.ts — since that module is being
 * actively developed in parallel by a concurrent effort and this file should not couple to its
 * in-flight state; it's a single stable constant so drift risk is minimal.
 */
const GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID = '62e90394-69f5-4237-9190-012177145e10';
const GLOBAL_ADMINISTRATOR_DISPLAY_NAME = 'global administrator';

/**
 * Well-known built-in "Guest User" (most restrictive) directory role template id. This is the
 * default/most-restricted of the three guest-access levels Microsoft documents (Guest User /
 * Guest User (most restrictive) / Member User) for `authorizationPolicy.guestUserRoleId`.
 * NOTE: verify against https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
 * if this control ever produces surprising results on a live tenant — recorded here as the
 * commonly documented value rather than independently re-derived from a live tenant.
 */
const RESTRICTED_GUEST_USER_ROLE_TEMPLATE_ID = '2af84b1e-32c8-42b7-82bc-daa82404023b';

/** Richer evaluator output; engine.ts flattens this into a ControlResult. */
export interface EvaluationOutcome {
  status: ControlStatus;
  detail: string;
  evidence?: Record<string, unknown>;
}

export type Evaluator = (signals: TenantCollectionResult) => EvaluationOutcome;

/** How stale an "atRisk" risky user must be before we consider it a FAIL rather than a grace-period PARTIAL. */
const RISKY_USER_STALENESS_DAYS = 7;

function daysBetween(isoA: string, isoB: string): number {
  const msPerDay = 1000 * 60 * 60 * 24;
  return Math.abs(new Date(isoA).getTime() - new Date(isoB).getTime()) / msPerDay;
}

/** True if `signals.errors` explicitly reports a collection failure for the given signal key. */
function collectorErroredFor(signals: TenantCollectionResult, signalKey: string): string | undefined {
  return signals.errors?.find((e) => e.signal === signalKey)?.message;
}

/**
 * Builds an UNKNOWN outcome for a missing/uncollected required signal, folding in
 * the collector's own error message when one was reported for that signal.
 */
function missingSignalOutcome(signals: TenantCollectionResult, signalKey: string, humanName: string): EvaluationOutcome {
  const collectorError = collectorErroredFor(signals, signalKey);
  return {
    status: 'UNKNOWN',
    detail: collectorError
      ? `${humanName} could not be evaluated: collector reported an error for "${signalKey}": ${collectorError}`
      : `${humanName} could not be evaluated: "${signalKey}" was not collected for this cycle.`,
    evidence: collectorError ? { signal: signalKey, collectorError } : { signal: signalKey },
  };
}

function isEnabled(policy: GraphConditionalAccessPolicy): boolean {
  return policy.state === 'enabled';
}

function grantsMfa(policy: GraphConditionalAccessPolicy): boolean {
  const controls = policy.grantControls?.builtInControls ?? [];
  return controls.some((c) => c.toLowerCase() === 'mfa');
}

function grantsBlock(policy: GraphConditionalAccessPolicy): boolean {
  const controls = policy.grantControls?.builtInControls ?? [];
  return controls.some((c) => c.toLowerCase() === 'block');
}

/** Best-effort read of `conditions.users.includeRoles` / `includeUsers` without assuming Graph's full condition schema. */
function conditionTargetsAllUsers(conditions: Record<string, unknown>): boolean {
  const users = conditions['users'] as Record<string, unknown> | undefined;
  const includeUsers = users?.['includeUsers'];
  return Array.isArray(includeUsers) && includeUsers.includes('All');
}

function conditionTargetsAdminRoles(conditions: Record<string, unknown>): boolean {
  const users = conditions['users'] as Record<string, unknown> | undefined;
  const includeRoles = users?.['includeRoles'];
  return Array.isArray(includeRoles) && includeRoles.length > 0;
}

/** Best-effort read of `conditions.clientAppTypes` / `conditions.applications` legacy-auth targeting. */
function conditionTargetsLegacyAuth(conditions: Record<string, unknown>): boolean {
  const clientAppTypes = conditions['clientAppTypes'];
  if (!Array.isArray(clientAppTypes)) return false;
  const legacyMarkers = ['exchangeActiveSync', 'other', 'legacy'];
  return clientAppTypes.some((t) => typeof t === 'string' && legacyMarkers.includes(t));
}

// ---------------------------------------------------------------------------
// mfa-admins-required
// ---------------------------------------------------------------------------

export function evaluateMfaForAdmins(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'MFA-for-admins');
  }
  const policies = signals.conditionalAccessPolicies;
  const enabled = policies.filter(isEnabled);
  const adminMfaPolicies = enabled.filter((p) => grantsMfa(p) && conditionTargetsAdminRoles(p.conditions));
  const allUsersMfaPolicies = enabled.filter((p) => grantsMfa(p) && conditionTargetsAllUsers(p.conditions));

  if (adminMfaPolicies.length > 0 || allUsersMfaPolicies.length > 0) {
    return {
      status: 'PASS',
      detail: adminMfaPolicies.length > 0
        ? `${adminMfaPolicies.length} enabled CA polic${adminMfaPolicies.length === 1 ? 'y requires' : 'ies require'} MFA for privileged roles.`
        : `An enabled CA policy requires MFA for all users, which covers admins.`,
      evidence: {
        adminTargetedPolicyIds: adminMfaPolicies.map((p) => p.id),
        allUsersTargetedPolicyIds: allUsersMfaPolicies.map((p) => p.id),
      },
    };
  }

  const reportOnlyAdminMfa = policies.filter(
    (p) => p.state === 'enabledForReportingButNotEnforced' && grantsMfa(p) && conditionTargetsAdminRoles(p.conditions)
  );
  if (reportOnlyAdminMfa.length > 0) {
    return {
      status: 'PARTIAL',
      detail: 'An MFA-for-admins policy exists but is only in report-only mode, not enforced.',
      evidence: { reportOnlyPolicyIds: reportOnlyAdminMfa.map((p) => p.id) },
    };
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy requires MFA for administrative roles.',
    evidence: { enabledPolicyCount: enabled.length },
  };
}

// ---------------------------------------------------------------------------
// mfa-all-users-required
// ---------------------------------------------------------------------------

export function evaluateMfaForAllUsers(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'MFA-for-all-users');
  }
  const policies = signals.conditionalAccessPolicies;
  const enabled = policies.filter(isEnabled);
  const allUsersMfaPolicies = enabled.filter((p) => grantsMfa(p) && conditionTargetsAllUsers(p.conditions));

  if (allUsersMfaPolicies.length > 0) {
    return {
      status: 'PASS',
      detail: `${allUsersMfaPolicies.length} enabled CA polic${allUsersMfaPolicies.length === 1 ? 'y requires' : 'ies require'} MFA for all users.`,
      evidence: { policyIds: allUsersMfaPolicies.map((p) => p.id) },
    };
  }

  const adminOnlyMfa = enabled.filter((p) => grantsMfa(p) && conditionTargetsAdminRoles(p.conditions));
  if (adminOnlyMfa.length > 0) {
    return {
      status: 'PARTIAL',
      detail: 'MFA is enforced for admin roles but no enabled policy extends the requirement to all users.',
      evidence: { adminOnlyPolicyIds: adminOnlyMfa.map((p) => p.id) },
    };
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy requires MFA for all users.',
    evidence: { enabledPolicyCount: enabled.length },
  };
}

// ---------------------------------------------------------------------------
// legacy-auth-blocked
// ---------------------------------------------------------------------------

export function evaluateLegacyAuthBlocked(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'Legacy authentication blocked');
  }
  const policies = signals.conditionalAccessPolicies;
  const enabledBlockingPolicies = policies.filter(
    (p) => isEnabled(p) && grantsBlock(p) && conditionTargetsLegacyAuth(p.conditions)
  );

  if (enabledBlockingPolicies.length > 0) {
    return {
      status: 'PASS',
      detail: `${enabledBlockingPolicies.length} enabled CA polic${enabledBlockingPolicies.length === 1 ? 'y blocks' : 'ies block'} legacy authentication clients.`,
      evidence: { policyIds: enabledBlockingPolicies.map((p) => p.id) },
    };
  }

  const reportOnlyBlockingPolicies = policies.filter(
    (p) => p.state === 'enabledForReportingButNotEnforced' && grantsBlock(p) && conditionTargetsLegacyAuth(p.conditions)
  );
  if (reportOnlyBlockingPolicies.length > 0) {
    return {
      status: 'PARTIAL',
      detail: 'A legacy-auth-blocking policy exists but is only in report-only mode, not enforced.',
      evidence: { reportOnlyPolicyIds: reportOnlyBlockingPolicies.map((p) => p.id) },
    };
  }

  // Corroborate with actual sign-in traffic if we have it: legacy auth sign-ins that succeeded
  // are strong evidence nothing is blocking them, even absent a clearly-shaped CA policy.
  if (signals.recentSignIns) {
    const legacyClientMarkers = ['imap', 'pop', 'smtp', 'exchangeactivesync', 'other clients'];
    const successfulLegacySignIns = signals.recentSignIns.filter(
      (s) => legacyClientMarkers.some((m) => s.clientAppUsed.toLowerCase().includes(m)) && s.conditionalAccessStatus === 'success'
    );
    if (successfulLegacySignIns.length > 0) {
      return {
        status: 'FAIL',
        detail: `${successfulLegacySignIns.length} successful sign-in(s) via legacy auth clients observed with no blocking CA policy in place.`,
        evidence: { sampleSignInIds: successfulLegacySignIns.slice(0, 10).map((s) => s.id) },
      };
    }
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy blocks legacy authentication clients.',
    evidence: { enabledPolicyCount: policies.filter(isEnabled).length },
  };
}

// ---------------------------------------------------------------------------
// privileged-roles-no-standing-access
// ---------------------------------------------------------------------------

export function evaluatePrivilegedRolesNoStandingAccess(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.privilegedRoleAssignments) {
    return missingSignalOutcome(signals, 'privilegedRoleAssignments', 'Privileged roles / no standing access');
  }
  const privileged = signals.privilegedRoleAssignments.filter((r) => r.isPrivileged);

  if (privileged.length === 0) {
    return {
      status: 'PASS',
      detail: 'No standing privileged role assignments were found.',
      evidence: { privilegedAssignmentCount: 0 },
    };
  }

  // Heuristic: standing assignments held directly by user principals are the risk;
  // group-based or service-principal-held roles are more plausibly governed by PIM/eligibility
  // elsewhere, so weight the user-held count more heavily.
  const userHeld = privileged.filter((r) => r.principalType === 'user');
  const hasCaProtectionForPrivileged =
    signals.conditionalAccessPolicies?.some(
      (p) => isEnabled(p) && (grantsMfa(p) || grantsBlock(p)) && conditionTargetsAdminRoles(p.conditions)
    ) ?? false;

  if (userHeld.length === 0) {
    return {
      status: 'PARTIAL',
      detail: `${privileged.length} privileged role assignment(s) exist, held by groups/service principals only (no direct user standing access detected). Verify eligibility/PIM configuration out-of-band.`,
      evidence: { privilegedAssignmentCount: privileged.length, userHeldCount: 0 },
    };
  }

  if (userHeld.length <= 2 && hasCaProtectionForPrivileged) {
    return {
      status: 'PARTIAL',
      detail: `${userHeld.length} user(s) hold standing privileged role assignments directly, but CA policy applies additional protection (MFA/block) to admin roles. Consider moving to just-in-time/PIM.`,
      evidence: { privilegedAssignmentCount: privileged.length, userHeldCount: userHeld.length },
    };
  }

  return {
    status: 'FAIL',
    detail: `${userHeld.length} user(s) hold standing (non-eligible) privileged role assignments with no compensating admin-targeted CA control detected. Standing access to privileged roles should require just-in-time activation/approval.`,
    evidence: {
      privilegedAssignmentCount: privileged.length,
      userHeldCount: userHeld.length,
      roleNames: [...new Set(userHeld.map((r) => r.roleName))],
    },
  };
}

// ---------------------------------------------------------------------------
// risky-users-addressed
// ---------------------------------------------------------------------------

export function evaluateRiskyUsersAddressed(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.riskyUsers) {
    return missingSignalOutcome(signals, 'riskyUsers', 'Risky users addressed');
  }
  const riskyUsers = signals.riskyUsers;

  if (riskyUsers.length === 0) {
    return {
      status: 'PASS',
      detail: 'No risky users reported by Entra ID Protection.',
      evidence: { riskyUserCount: 0 },
    };
  }

  const atRisk = riskyUsers.filter((u) => u.riskState === 'atRisk' || u.riskState === 'confirmedCompromised');
  const addressed = riskyUsers.filter((u) => u.riskState === 'remediated' || u.riskState === 'confirmedSafe' || u.riskState === 'dismissed');

  if (atRisk.length === 0) {
    return {
      status: 'PASS',
      detail: `All ${riskyUsers.length} flagged user(s) have been remediated, confirmed safe, or dismissed.`,
      evidence: { riskyUserCount: riskyUsers.length, addressedCount: addressed.length },
    };
  }

  const staleAtRisk = atRisk.filter((u) => daysBetween(u.riskLastUpdatedDateTime, signals.collectedAt) >= RISKY_USER_STALENESS_DAYS);
  const confirmedCompromised = atRisk.filter((u) => u.riskState === 'confirmedCompromised');

  if (confirmedCompromised.length > 0 || staleAtRisk.length > 0) {
    return {
      status: 'FAIL',
      detail:
        confirmedCompromised.length > 0
          ? `${confirmedCompromised.length} user(s) are confirmed compromised and require immediate remediation.`
          : `${staleAtRisk.length} user(s) have been at-risk for ${RISKY_USER_STALENESS_DAYS}+ days without remediation.`,
      evidence: {
        atRiskCount: atRisk.length,
        staleAtRiskCount: staleAtRisk.length,
        confirmedCompromisedCount: confirmedCompromised.length,
        userPrincipalNames: atRisk.slice(0, 10).map((u) => u.userPrincipalName),
      },
    };
  }

  return {
    status: 'PARTIAL',
    detail: `${atRisk.length} user(s) are currently at-risk but within the ${RISKY_USER_STALENESS_DAYS}-day remediation grace period.`,
    evidence: { atRiskCount: atRisk.length },
  };
}

// ---------------------------------------------------------------------------
// secure-score-above-threshold
// ---------------------------------------------------------------------------

const SECURE_SCORE_PASS_THRESHOLD = 0.7; // 70%
const SECURE_SCORE_PARTIAL_THRESHOLD = 0.5; // 50%

export function evaluateSecureScoreAboveThreshold(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.secureScore) {
    return missingSignalOutcome(signals, 'secureScore', 'Secure Score above threshold');
  }
  const { currentScore, maxScore } = signals.secureScore;
  if (maxScore <= 0) {
    return {
      status: 'UNKNOWN',
      detail: 'Secure Score maxScore is zero or invalid; ratio cannot be computed.',
      evidence: { currentScore, maxScore },
    };
  }
  const ratio = currentScore / maxScore;

  if (ratio >= SECURE_SCORE_PASS_THRESHOLD) {
    return {
      status: 'PASS',
      detail: `Secure Score is ${(ratio * 100).toFixed(1)}% (${currentScore}/${maxScore}), at or above the ${SECURE_SCORE_PASS_THRESHOLD * 100}% threshold.`,
      evidence: { currentScore, maxScore, ratio },
    };
  }
  if (ratio >= SECURE_SCORE_PARTIAL_THRESHOLD) {
    return {
      status: 'PARTIAL',
      detail: `Secure Score is ${(ratio * 100).toFixed(1)}% (${currentScore}/${maxScore}), below the ${SECURE_SCORE_PASS_THRESHOLD * 100}% target but above ${SECURE_SCORE_PARTIAL_THRESHOLD * 100}%.`,
      evidence: { currentScore, maxScore, ratio },
    };
  }
  return {
    status: 'FAIL',
    detail: `Secure Score is ${(ratio * 100).toFixed(1)}% (${currentScore}/${maxScore}), below the ${SECURE_SCORE_PARTIAL_THRESHOLD * 100}% floor.`,
    evidence: { currentScore, maxScore, ratio },
  };
}

// ---------------------------------------------------------------------------
// guest-external-access-reviewed
// ---------------------------------------------------------------------------

export function evaluateGuestAccessReviewed(_signals: TenantCollectionResult): EvaluationOutcome {
  // We don't currently collect an access-reviews or guest-user-inventory signal, so this
  // control is best-effort: report UNKNOWN rather than guessing at compliance.
  return {
    status: 'UNKNOWN',
    detail:
      'Guest/external access review status cannot be determined: no access-reviews or guest-user-inventory signal is collected yet.',
    evidence: { missingSignals: ['accessReviews', 'guestUsers'] },
  };
}

// ---------------------------------------------------------------------------
// weak-authentication-methods-disabled
// ---------------------------------------------------------------------------

function findMethodConfig(policy: GraphAuthenticationMethodsPolicy, id: string) {
  return policy.authenticationMethodConfigurations.find((c) => c.id.toLowerCase() === id.toLowerCase());
}

export function evaluateWeakAuthMethodsDisabled(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authenticationMethodsPolicy) {
    return missingSignalOutcome(signals, 'authenticationMethodsPolicy', 'Weak authentication methods disabled');
  }
  const policy = signals.authenticationMethodsPolicy;
  const weakIds = ['Sms', 'Voice', 'Email'];
  const configs = weakIds.map((id) => ({ id, config: findMethodConfig(policy, id) }));
  const enabledWeak = configs.filter((c) => c.config?.state === 'enabled');

  if (enabledWeak.length === 0) {
    return {
      status: 'PASS',
      detail: 'SMS, Voice Call, and Email OTP authentication methods are all disabled tenant-wide.',
      evidence: { checkedMethods: weakIds },
    };
  }

  return {
    status: 'FAIL',
    detail: `${enabledWeak.length} weak/phishable authentication method(s) are still enabled: ${enabledWeak.map((c) => c.id).join(', ')}.`,
    evidence: { enabledWeakMethods: enabledWeak.map((c) => c.id) },
  };
}

// ---------------------------------------------------------------------------
// authenticator-number-matching-required
// ---------------------------------------------------------------------------

export function evaluateAuthenticatorNumberMatching(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authenticationMethodsPolicy) {
    return missingSignalOutcome(signals, 'authenticationMethodsPolicy', 'Authenticator number matching required');
  }
  const config = findMethodConfig(signals.authenticationMethodsPolicy, 'MicrosoftAuthenticator');
  if (!config || !config.featureSettings) {
    return {
      status: 'UNKNOWN',
      detail:
        'Authenticator number matching could not be evaluated: no "MicrosoftAuthenticator" configuration (or its featureSettings) was present in the authentication methods policy.',
      evidence: { hasConfig: !!config },
    };
  }
  const state = config.featureSettings.numberMatchingRequiredState?.state;
  if (state === 'enabled') {
    return {
      status: 'PASS',
      detail: 'Microsoft Authenticator push notifications require number matching.',
      evidence: { numberMatchingState: state },
    };
  }
  if (state === 'disabled') {
    return {
      status: 'FAIL',
      detail: 'Microsoft Authenticator is enabled but number matching is not required, leaving push notifications vulnerable to MFA-fatigue approval.',
      evidence: { numberMatchingState: state },
    };
  }
  return {
    status: 'UNKNOWN',
    detail: 'Authenticator number matching could not be evaluated: numberMatchingRequiredState was not reported.',
    evidence: { config },
  };
}

// ---------------------------------------------------------------------------
// fido2-attestation-enforced
// ---------------------------------------------------------------------------

export function evaluateFido2AttestationEnforced(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authenticationMethodsPolicy) {
    return missingSignalOutcome(signals, 'authenticationMethodsPolicy', 'FIDO2 attestation enforced');
  }
  const config = findMethodConfig(signals.authenticationMethodsPolicy, 'Fido2');
  if (!config) {
    return {
      status: 'UNKNOWN',
      detail: 'FIDO2 attestation could not be evaluated: no "Fido2" configuration was present in the authentication methods policy.',
      evidence: {},
    };
  }
  if (config.state === 'disabled') {
    return {
      status: 'NOT_APPLICABLE',
      detail: 'FIDO2 security keys are not enabled as an authentication method, so attestation enforcement does not apply.',
      evidence: { fido2State: config.state },
    };
  }
  if (config.isAttestationEnforced === true) {
    return {
      status: 'PASS',
      detail: 'FIDO2 is enabled and key attestation is enforced.',
      evidence: { fido2State: config.state, isAttestationEnforced: true },
    };
  }
  return {
    status: 'FAIL',
    detail: 'FIDO2 is enabled but key attestation is not enforced, allowing registration of unvetted authenticator models.',
    evidence: { fido2State: config.state, isAttestationEnforced: config.isAttestationEnforced ?? null },
  };
}

// ---------------------------------------------------------------------------
// phishing-resistant-mfa-required
// ---------------------------------------------------------------------------

function grantsPhishingResistantAuthStrength(policy: GraphConditionalAccessPolicy): boolean {
  return !!policy.grantControls?.authenticationStrength?.id;
}

export function evaluatePhishingResistantMfaRequired(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'Phishing-resistant MFA required');
  }
  const policies = signals.conditionalAccessPolicies;
  const enabled = policies.filter(isEnabled);
  const strengthPolicies = enabled.filter(grantsPhishingResistantAuthStrength);
  const broadStrengthPolicies = strengthPolicies.filter((p) => conditionTargetsAllUsers(p.conditions));

  if (broadStrengthPolicies.length > 0) {
    return {
      status: 'PASS',
      detail: `${broadStrengthPolicies.length} enabled CA polic${broadStrengthPolicies.length === 1 ? 'y requires' : 'ies require'} a phishing-resistant authentication strength for all users.`,
      evidence: { policyIds: broadStrengthPolicies.map((p) => p.id) },
    };
  }

  if (strengthPolicies.length > 0) {
    return {
      status: 'PARTIAL',
      detail: `${strengthPolicies.length} enabled CA polic${strengthPolicies.length === 1 ? 'y requires' : 'ies require'} a phishing-resistant authentication strength, but only for a subset of users, not the full user population.`,
      evidence: { policyIds: strengthPolicies.map((p) => p.id) },
    };
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy requires a phishing-resistant authentication strength.',
    evidence: { enabledPolicyCount: enabled.length },
  };
}

// ---------------------------------------------------------------------------
// device-code-flow-blocked
// ---------------------------------------------------------------------------

export function evaluateDeviceCodeFlowBlocked(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'Device code flow blocked');
  }
  // As of this writing, Graph's `conditionalAccessPolicy.conditions` exposes device-code-flow
  // targeting via `conditions.authenticationFlows.transferMethods` (a relatively new field), but
  // we don't have confidence this exact shape is what the collector will actually receive/pass
  // through, and guessing at a field name that turns out wrong is worse than surfacing UNKNOWN.
  // Report UNKNOWN rather than asserting a PASS/FAIL we can't back with a well-documented check.
  return {
    status: 'UNKNOWN',
    detail:
      'Device-code authentication flow blocking cannot be reliably evaluated yet: the loosely-typed CA `conditions` object does not have a confirmed, stable field for authentication-flow targeting in this codebase. Needs verification against a live tenant/Graph schema before a PASS/FAIL determination can be trusted.',
    evidence: { enabledPolicyCount: signals.conditionalAccessPolicies.filter(isEnabled).length },
  };
}

// ---------------------------------------------------------------------------
// managed-device-required-for-mfa-registration
// ---------------------------------------------------------------------------

export function evaluateManagedDeviceRequiredForMfaRegistration(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'Managed device required for MFA registration');
  }
  // Same caveat as device-code-flow-blocked: Graph models this as `conditions.userActions`
  // containing "urn:user:registersecurityinfo", but we don't have confirmed visibility into
  // whether the collector surfaces that field verbatim under this loosely-typed bag. Rather than
  // guess at a field/string that might not match what's actually collected, report UNKNOWN.
  return {
    status: 'UNKNOWN',
    detail:
      'Managed-device-for-security-info-registration cannot be reliably evaluated yet: no confirmed, stable field for the "register security information" user action was identified on the CA policy `conditions` object in this codebase. Needs verification before a PASS/FAIL determination can be trusted.',
    evidence: { enabledPolicyCount: signals.conditionalAccessPolicies.filter(isEnabled).length },
  };
}

// ---------------------------------------------------------------------------
// high-risk-users-blocked-by-ca / high-risk-signins-blocked-by-ca
// ---------------------------------------------------------------------------

function conditionIncludesRiskLevel(conditions: Record<string, unknown>, field: string, level: string): boolean {
  const levels = conditions[field];
  return Array.isArray(levels) && levels.some((l) => typeof l === 'string' && l.toLowerCase() === level.toLowerCase());
}

export function evaluateHighRiskUsersBlockedByCa(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'High-risk users blocked by Conditional Access');
  }
  const enabled = signals.conditionalAccessPolicies.filter(isEnabled);
  const blockingHighUserRisk = enabled.filter(
    (p) => grantsBlock(p) && conditionIncludesRiskLevel(p.conditions, 'userRiskLevels', 'high')
  );

  if (blockingHighUserRisk.length > 0) {
    return {
      status: 'PASS',
      detail: `${blockingHighUserRisk.length} enabled CA polic${blockingHighUserRisk.length === 1 ? 'y blocks' : 'ies block'} sign-in for users at high risk.`,
      evidence: { policyIds: blockingHighUserRisk.map((p) => p.id) },
    };
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy blocks sign-in for users flagged at high risk.',
    evidence: { enabledPolicyCount: enabled.length },
  };
}

export function evaluateHighRiskSignInsBlockedByCa(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'conditionalAccessPolicies', 'High-risk sign-ins blocked by Conditional Access');
  }
  const enabled = signals.conditionalAccessPolicies.filter(isEnabled);
  const blockingHighSignInRisk = enabled.filter(
    (p) => grantsBlock(p) && conditionIncludesRiskLevel(p.conditions, 'signInRiskLevels', 'high')
  );

  if (blockingHighSignInRisk.length > 0) {
    return {
      status: 'PASS',
      detail: `${blockingHighSignInRisk.length} enabled CA polic${blockingHighSignInRisk.length === 1 ? 'y blocks' : 'ies block'} sign-ins at high session risk.`,
      evidence: { policyIds: blockingHighSignInRisk.map((p) => p.id) },
    };
  }

  return {
    status: 'FAIL',
    detail: 'No enabled conditional access policy blocks sign-ins flagged at high session (sign-in) risk.',
    evidence: { enabledPolicyCount: enabled.length },
  };
}

// ---------------------------------------------------------------------------
// global-admin-count-in-range
// ---------------------------------------------------------------------------

const GLOBAL_ADMIN_MIN_COUNT = 2;
const GLOBAL_ADMIN_MAX_COUNT = 8;

export function evaluateGlobalAdminCountInRange(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.privilegedRoleAssignments) {
    return missingSignalOutcome(signals, 'privilegedRoleAssignments', 'Global Administrator count in range');
  }
  const globalAdmins = signals.privilegedRoleAssignments.filter(
    (r) =>
      r.roleDefinitionId === GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID ||
      r.roleName.toLowerCase() === GLOBAL_ADMINISTRATOR_DISPLAY_NAME
  );
  const count = globalAdmins.length;

  if (count < GLOBAL_ADMIN_MIN_COUNT) {
    return {
      status: 'FAIL',
      detail: `Only ${count} active Global Administrator assignment(s) found; at least ${GLOBAL_ADMIN_MIN_COUNT} are recommended to avoid a single point of failure/lockout.`,
      evidence: { globalAdminCount: count, min: GLOBAL_ADMIN_MIN_COUNT, max: GLOBAL_ADMIN_MAX_COUNT },
    };
  }
  if (count > GLOBAL_ADMIN_MAX_COUNT) {
    return {
      status: 'FAIL',
      detail: `${count} active Global Administrator assignments found, exceeding the recommended maximum of ${GLOBAL_ADMIN_MAX_COUNT}; this unnecessarily broadens blast radius.`,
      evidence: { globalAdminCount: count, min: GLOBAL_ADMIN_MIN_COUNT, max: GLOBAL_ADMIN_MAX_COUNT },
    };
  }
  return {
    status: 'PASS',
    detail: `${count} active Global Administrator assignment(s) found, within the recommended range of ${GLOBAL_ADMIN_MIN_COUNT}-${GLOBAL_ADMIN_MAX_COUNT}.`,
    evidence: { globalAdminCount: count, min: GLOBAL_ADMIN_MIN_COUNT, max: GLOBAL_ADMIN_MAX_COUNT },
  };
}

// ---------------------------------------------------------------------------
// user-app-registration-restricted
// ---------------------------------------------------------------------------

export function evaluateUserAppRegistrationRestricted(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authorizationPolicy) {
    return missingSignalOutcome(signals, 'authorizationPolicy', 'User app registration restricted');
  }
  const allowedToCreateApps = signals.authorizationPolicy.defaultUserRolePermissions?.allowedToCreateApps;
  if (allowedToCreateApps === undefined) {
    return {
      status: 'UNKNOWN',
      detail: 'User app registration restriction could not be evaluated: defaultUserRolePermissions.allowedToCreateApps was not reported.',
      evidence: {},
    };
  }
  if (allowedToCreateApps === false) {
    return {
      status: 'PASS',
      detail: 'Non-admin users are not allowed to register new application registrations.',
      evidence: { allowedToCreateApps },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Non-admin users are allowed to register new application registrations.',
    evidence: { allowedToCreateApps },
  };
}

// ---------------------------------------------------------------------------
// user-consent-to-apps-restricted
// ---------------------------------------------------------------------------

export function evaluateUserConsentToAppsRestricted(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authorizationPolicy) {
    return missingSignalOutcome(signals, 'authorizationPolicy', 'User consent to apps restricted');
  }
  const policies = signals.authorizationPolicy.defaultUserRolePermissions?.permissionGrantPoliciesAssigned;
  if (policies === undefined) {
    return {
      status: 'UNKNOWN',
      detail: 'User consent restriction could not be evaluated: defaultUserRolePermissions.permissionGrantPoliciesAssigned was not reported.',
      evidence: {},
    };
  }
  if (policies.length === 0) {
    return {
      status: 'PASS',
      detail: 'No default user-consent permission-grant policy is assigned; users cannot self-consent to app permissions.',
      evidence: { permissionGrantPoliciesAssigned: policies },
    };
  }
  // We're not fully certain of the exact policy id string(s) Microsoft uses to represent
  // "unrestricted user consent allowed" (e.g. "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
  // versus a tightly admin-scoped custom policy, so rather than guess, treat any non-empty value
  // as needing human review instead of asserting FAIL.
  return {
    status: 'PARTIAL',
    detail:
      `${policies.length} permission-grant polic${policies.length === 1 ? 'y is' : 'ies are'} assigned to the default user role ` +
      '(policy id(s): ' + policies.join(', ') + '). Whether this represents unrestricted user consent or a tightly-scoped admin-approved ' +
      'policy could not be determined with certainty from the policy id string alone — needs manual review.',
    evidence: { permissionGrantPoliciesAssigned: policies },
  };
}

// ---------------------------------------------------------------------------
// guest-user-restricted-role
// ---------------------------------------------------------------------------

export function evaluateGuestUserRestrictedRole(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authorizationPolicy) {
    return missingSignalOutcome(signals, 'authorizationPolicy', 'Guest user restricted role');
  }
  const { guestUserRoleId } = signals.authorizationPolicy;
  if (!guestUserRoleId) {
    return {
      status: 'UNKNOWN',
      detail: 'Guest user role could not be evaluated: guestUserRoleId was not reported.',
      evidence: {},
    };
  }
  if (guestUserRoleId === RESTRICTED_GUEST_USER_ROLE_TEMPLATE_ID) {
    return {
      status: 'PASS',
      detail: 'Guest users are assigned the most-restricted built-in guest role.',
      evidence: { guestUserRoleId },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Guest users are not assigned the most-restricted built-in guest role; they may have broader directory visibility than intended.',
    evidence: { guestUserRoleId, expectedRestrictedRoleId: RESTRICTED_GUEST_USER_ROLE_TEMPLATE_ID },
  };
}

// ---------------------------------------------------------------------------
// guest-invites-restricted-to-admins
// ---------------------------------------------------------------------------

export function evaluateGuestInvitesRestrictedToAdmins(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.authorizationPolicy) {
    return missingSignalOutcome(signals, 'authorizationPolicy', 'Guest invites restricted to admins');
  }
  const { allowInvitesFrom } = signals.authorizationPolicy;

  if (allowInvitesFrom === 'none' || allowInvitesFrom === 'adminsAndGuestInviters') {
    return {
      status: 'PASS',
      detail: `Guest invitations are restricted (allowInvitesFrom = "${allowInvitesFrom}").`,
      evidence: { allowInvitesFrom },
    };
  }
  if (allowInvitesFrom === 'adminsGuestInvitersAndAllMembers') {
    return {
      status: 'PARTIAL',
      detail: 'Guest invitations are allowed from all members, not just admins/designated inviters.',
      evidence: { allowInvitesFrom },
    };
  }
  if (allowInvitesFrom === 'everyone') {
    return {
      status: 'FAIL',
      detail: 'Guest invitations are allowed from everyone, including guests themselves.',
      evidence: { allowInvitesFrom },
    };
  }
  return {
    status: 'UNKNOWN',
    detail: `Guest invite restriction could not be evaluated: unrecognized allowInvitesFrom value "${String(allowInvitesFrom)}".`,
    evidence: { allowInvitesFrom },
  };
}

// ---------------------------------------------------------------------------
// password-never-expires-policy
// ---------------------------------------------------------------------------

/** Sentinel Graph uses for "password never expires" on `passwordValidityPeriodInDays`. */
const PASSWORD_NEVER_EXPIRES_SENTINEL = 2147483647;

export function evaluatePasswordNeverExpiresPolicy(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.domains) {
    return missingSignalOutcome(signals, 'domains', 'Password never-expires policy');
  }
  const verifiedDomains = signals.domains.filter((d) => d.isVerified);
  if (verifiedDomains.length === 0) {
    return {
      status: 'UNKNOWN',
      detail: 'Password expiration policy could not be evaluated: no verified domains were reported.',
      evidence: {},
    };
  }

  const expiringDomains = verifiedDomains.filter((d) => {
    const days = d.passwordValidityPeriodInDays;
    return days !== null && days !== undefined && days < PASSWORD_NEVER_EXPIRES_SENTINEL;
  });

  if (expiringDomains.length === 0) {
    return {
      status: 'PASS',
      detail: `All ${verifiedDomains.length} verified domain(s) are configured with a never-expiring password policy.`,
      evidence: { verifiedDomainCount: verifiedDomains.length },
    };
  }

  return {
    status: 'FAIL',
    detail: `${expiringDomains.length} of ${verifiedDomains.length} verified domain(s) enforce finite password expiration, contrary to NIST 800-63B / OMB M-22-09 guidance.`,
    evidence: {
      expiringDomains: expiringDomains.map((d) => ({ id: d.id, passwordValidityPeriodInDays: d.passwordValidityPeriodInDays })),
    },
  };
}

// ---------------------------------------------------------------------------
// app-registration-credential-hygiene
// ---------------------------------------------------------------------------

const SECRET_MAX_LIFETIME_DAYS = 180;
const CERT_MAX_LIFETIME_DAYS = 365;

function credentialLifetimeDays(startDateTime?: string | null, endDateTime?: string | null): number | undefined {
  if (!startDateTime || !endDateTime) return undefined;
  return daysBetween(startDateTime, endDateTime);
}

export function evaluateAppRegistrationCredentialHygiene(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.applications) {
    return missingSignalOutcome(signals, 'applications', 'App registration credential hygiene');
  }
  const apps = signals.applications;

  const appsWithLongLivedSecrets: Array<{ id: string; displayName: string; keyId: string; lifetimeDays: number }> = [];
  const appsWithLongLivedCerts: Array<{ id: string; displayName: string; keyId: string; lifetimeDays: number }> = [];
  const appsWithAnySecret = new Set<string>();

  for (const app of apps) {
    for (const cred of app.passwordCredentials) {
      appsWithAnySecret.add(app.id);
      const lifetime = credentialLifetimeDays(cred.startDateTime, cred.endDateTime);
      if (lifetime !== undefined && lifetime > SECRET_MAX_LIFETIME_DAYS) {
        appsWithLongLivedSecrets.push({ id: app.id, displayName: app.displayName, keyId: cred.keyId, lifetimeDays: lifetime });
      }
    }
    for (const cred of app.keyCredentials) {
      const lifetime = credentialLifetimeDays(cred.startDateTime, cred.endDateTime);
      if (lifetime !== undefined && lifetime > CERT_MAX_LIFETIME_DAYS) {
        appsWithLongLivedCerts.push({ id: app.id, displayName: app.displayName, keyId: cred.keyId, lifetimeDays: lifetime });
      }
    }
  }

  if (appsWithLongLivedSecrets.length > 0 || appsWithLongLivedCerts.length > 0) {
    return {
      status: 'FAIL',
      detail:
        `${appsWithLongLivedSecrets.length} app registration credential(s) exceed the ${SECRET_MAX_LIFETIME_DAYS}-day client-secret lifetime bound, and ` +
        `${appsWithLongLivedCerts.length} exceed the ${CERT_MAX_LIFETIME_DAYS}-day certificate lifetime bound.`,
      evidence: { appsWithLongLivedSecrets, appsWithLongLivedCerts },
    };
  }

  if (appsWithAnySecret.size > 0) {
    return {
      status: 'PARTIAL',
      detail: `${appsWithAnySecret.size} app registration(s) use client secrets (rather than certificates only), though all are within the ${SECRET_MAX_LIFETIME_DAYS}-day lifetime bound. Prefer certificate credentials where feasible.`,
      evidence: { appCountWithSecrets: appsWithAnySecret.size },
    };
  }

  return {
    status: 'PASS',
    detail: 'No app registrations use client secrets, and all credential lifetimes are within bounds.',
    evidence: { appCount: apps.length },
  };
}

// ---------------------------------------------------------------------------
// privileged-service-principal-no-owners / privileged-service-principal-no-client-secrets
// ---------------------------------------------------------------------------

export function evaluatePrivilegedServicePrincipalNoOwners(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.privilegedServicePrincipals) {
    return missingSignalOutcome(signals, 'privilegedServicePrincipals', 'Privileged service principal no owners');
  }
  const sps = signals.privilegedServicePrincipals;
  if (sps.length === 0) {
    return {
      status: 'PASS',
      detail: 'No service principals hold a permanent privileged directory role.',
      evidence: { privilegedServicePrincipalCount: 0 },
    };
  }
  const withOwners = sps.filter((sp) => sp.ownerIds.length > 0);
  if (withOwners.length === 0) {
    return {
      status: 'PASS',
      detail: `All ${sps.length} privileged service principal(s) have zero owners.`,
      evidence: { privilegedServicePrincipalCount: sps.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${withOwners.length} of ${sps.length} privileged service principal(s) have at least one owner, who could rotate credentials and inherit the privileged role.`,
    evidence: {
      servicePrincipalsWithOwners: withOwners.map((sp) => ({ id: sp.id, displayName: sp.displayName, ownerCount: sp.ownerIds.length })),
    },
  };
}

export function evaluatePrivilegedServicePrincipalNoClientSecrets(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.privilegedServicePrincipals) {
    return missingSignalOutcome(signals, 'privilegedServicePrincipals', 'Privileged service principal no client secrets');
  }
  const sps = signals.privilegedServicePrincipals;
  if (sps.length === 0) {
    return {
      status: 'PASS',
      detail: 'No service principals hold a permanent privileged directory role.',
      evidence: { privilegedServicePrincipalCount: 0 },
    };
  }
  const withSecrets = sps.filter((sp) => sp.passwordCredentials.length > 0);
  if (withSecrets.length === 0) {
    return {
      status: 'PASS',
      detail: `None of the ${sps.length} privileged service principal(s) use client secrets.`,
      evidence: { privilegedServicePrincipalCount: sps.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${withSecrets.length} of ${sps.length} privileged service principal(s) authenticate via client secret rather than certificate/managed identity.`,
    evidence: {
      servicePrincipalsWithSecrets: withSecrets.map((sp) => ({ id: sp.id, displayName: sp.displayName, secretCount: sp.passwordCredentials.length })),
    },
  };
}

// ---------------------------------------------------------------------------
// non-privileged-users-mfa-registered
// ---------------------------------------------------------------------------

// Thresholds are a judgment call (no single authoritative source mandates a specific percentage),
// chosen consistently with this file's other threshold-based evaluator
// (see SECURE_SCORE_PASS_THRESHOLD / SECURE_SCORE_PARTIAL_THRESHOLD above): PASS requires near-total
// coverage since MFA registration gates future enforcement; PARTIAL allows meaningful but incomplete
// rollout; anything further behind is a FAIL warranting active remediation.
const NON_PRIVILEGED_MFA_PASS_THRESHOLD = 0.95;
const NON_PRIVILEGED_MFA_PARTIAL_THRESHOLD = 0.8;

export function evaluateNonPrivilegedUsersMfaRegistered(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.userRegistrationDetails) {
    return missingSignalOutcome(signals, 'userRegistrationDetails', 'Non-privileged users MFA registered');
  }
  const nonPrivileged = signals.userRegistrationDetails.filter((u) => !u.isAdmin);
  if (nonPrivileged.length === 0) {
    return {
      status: 'UNKNOWN',
      detail: 'Non-privileged user MFA registration could not be evaluated: no non-admin users were reported in registration details.',
      evidence: {},
    };
  }
  const registeredCount = nonPrivileged.filter((u) => u.isMfaRegistered).length;
  const ratio = registeredCount / nonPrivileged.length;

  if (ratio >= NON_PRIVILEGED_MFA_PASS_THRESHOLD) {
    return {
      status: 'PASS',
      detail: `${(ratio * 100).toFixed(1)}% (${registeredCount}/${nonPrivileged.length}) of non-privileged users have an MFA method registered.`,
      evidence: { registeredCount, totalCount: nonPrivileged.length, ratio },
    };
  }
  if (ratio >= NON_PRIVILEGED_MFA_PARTIAL_THRESHOLD) {
    return {
      status: 'PARTIAL',
      detail: `${(ratio * 100).toFixed(1)}% (${registeredCount}/${nonPrivileged.length}) of non-privileged users have an MFA method registered, below the ${NON_PRIVILEGED_MFA_PASS_THRESHOLD * 100}% target.`,
      evidence: { registeredCount, totalCount: nonPrivileged.length, ratio },
    };
  }
  return {
    status: 'FAIL',
    detail: `Only ${(ratio * 100).toFixed(1)}% (${registeredCount}/${nonPrivileged.length}) of non-privileged users have an MFA method registered, below the ${NON_PRIVILEGED_MFA_PARTIAL_THRESHOLD * 100}% floor.`,
    evidence: { registeredCount, totalCount: nonPrivileged.length, ratio },
  };
}

// ---------------------------------------------------------------------------
// admin-consent-workflow-required
// ---------------------------------------------------------------------------

export function evaluateAdminConsentWorkflowRequired(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.adminConsentRequestPolicy) {
    return missingSignalOutcome(signals, 'adminConsentRequestPolicy', 'Admin consent workflow required');
  }
  const { isEnabled: policyEnabled, notifyReviewers } = signals.adminConsentRequestPolicy;

  if (!policyEnabled) {
    return {
      status: 'FAIL',
      detail: 'The admin consent request workflow is not enabled; users blocked from self-consenting have no path to request access review.',
      evidence: { isEnabled: policyEnabled, notifyReviewers },
    };
  }
  if (notifyReviewers) {
    return {
      status: 'PASS',
      detail: 'The admin consent request workflow is enabled and reviewers are notified of pending requests.',
      evidence: { isEnabled: policyEnabled, notifyReviewers },
    };
  }
  return {
    status: 'PARTIAL',
    detail: 'The admin consent request workflow is enabled, but reviewers are not notified of pending requests, risking requests going unreviewed.',
    evidence: { isEnabled: policyEnabled, notifyReviewers },
  };
}

// ---------------------------------------------------------------------------
// security-defaults-or-ca-baseline-enabled
// ---------------------------------------------------------------------------

export function evaluateSecurityDefaultsOrCaBaseline(signals: TenantCollectionResult): EvaluationOutcome {
  if (!signals.securityDefaultsPolicy && !signals.conditionalAccessPolicies) {
    return missingSignalOutcome(signals, 'securityDefaultsPolicy', 'Security defaults or CA baseline enabled');
  }

  if (signals.securityDefaultsPolicy?.isEnabled === true) {
    return {
      status: 'PASS',
      detail: 'Entra ID Security Defaults are enabled, providing a tenant-wide identity security baseline.',
      evidence: { securityDefaultsEnabled: true },
    };
  }

  // Reuse the same "broad enabled CA policy requires MFA for all users" logic that
  // evaluateMfaForAllUsers uses, as a proxy for "equivalent CA baseline in place", rather than
  // duplicating the underlying policy-matching logic here.
  if (signals.conditionalAccessPolicies) {
    const mfaBaseline = evaluateMfaForAllUsers(signals);
    if (mfaBaseline.status === 'PASS') {
      return {
        status: 'PASS',
        detail: 'Security Defaults are disabled, but an enabled Conditional Access policy provides equivalent broad MFA coverage for all users.',
        evidence: { securityDefaultsEnabled: signals.securityDefaultsPolicy?.isEnabled ?? null, caBaselineProxy: mfaBaseline.evidence },
      };
    }
  }

  if (!signals.securityDefaultsPolicy) {
    return missingSignalOutcome(signals, 'securityDefaultsPolicy', 'Security defaults or CA baseline enabled');
  }

  return {
    status: 'FAIL',
    detail: 'Security Defaults are disabled and no enabled Conditional Access policy provides an equivalent broad MFA baseline.',
    evidence: { securityDefaultsEnabled: signals.securityDefaultsPolicy.isEnabled },
  };
}

// ---------------------------------------------------------------------------
// Exchange Online / Security & Compliance / Microsoft Teams evaluators.
// Signals live at signals.exoTeams.{exoCompliance,teams} — see src/types/exoTeams.ts.
// Every evaluator below returns UNKNOWN via missingSignalOutcome for any
// undefined signal at any level (exoTeams, exoCompliance/teams, or the specific
// field), consistent with the file-level "never infer from absence" rule.
// ---------------------------------------------------------------------------

function exoCompliance(signals: TenantCollectionResult): ExoComplianceCollectionResult | undefined {
  return signals.exoTeams?.exoCompliance;
}

function teams(signals: TenantCollectionResult): TeamsCollectionResult | undefined {
  return signals.exoTeams?.teams;
}

// ---------------------------------------------------------------------------
// dkim-signing-enabled-all-domains
// ---------------------------------------------------------------------------

export function evaluateDkimSigningEnabledAllDomains(signals: TenantCollectionResult): EvaluationOutcome {
  const dkimConfigs = exoCompliance(signals)?.dkimConfigs;
  if (!dkimConfigs) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.dkimConfigs', 'DKIM signing enabled for all domains');
  }
  const disabled = dkimConfigs.filter((d) => !d.enabled);
  if (disabled.length === 0) {
    return {
      status: 'PASS',
      detail: `DKIM signing is enabled for all ${dkimConfigs.length} domain(s).`,
      evidence: { domainCount: dkimConfigs.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `DKIM signing is disabled for ${disabled.length} of ${dkimConfigs.length} domain(s).`,
    evidence: { disabledDomains: disabled.map((d) => d.domain) },
  };
}

// ---------------------------------------------------------------------------
// dmarc-policy-reject
// ---------------------------------------------------------------------------

export function evaluateDmarcPolicyReject(signals: TenantCollectionResult): EvaluationOutcome {
  const dmarcConfigs = exoCompliance(signals)?.dmarcConfigs;
  if (!dmarcConfigs) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.dmarcConfigs', 'DMARC policy set to reject');
  }
  // A missing DMARC record (policy: null) on a domain we actually checked is itself the
  // finding — it means the domain has no DMARC enforcement at all — so it counts as a FAIL
  // input here, not UNKNOWN. UNKNOWN is reserved for the whole signal being uncollected (above).
  const notReject = dmarcConfigs.filter((d) => d.policy !== 'reject');
  if (notReject.length === 0) {
    return {
      status: 'PASS',
      detail: `All ${dmarcConfigs.length} domain(s) publish a DMARC record with policy "reject".`,
      evidence: { domainCount: dmarcConfigs.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${notReject.length} of ${dmarcConfigs.length} domain(s) do not enforce a DMARC "reject" policy.`,
    evidence: {
      nonRejectDomains: notReject.map((d) => ({ domain: d.domain, policy: d.policy })),
    },
  };
}

// ---------------------------------------------------------------------------
// smtp-auth-disabled-tenant-wide
// ---------------------------------------------------------------------------

export function evaluateSmtpAuthDisabledTenantWide(signals: TenantCollectionResult): EvaluationOutcome {
  const orgConfig = exoCompliance(signals)?.organizationMailConfig;
  if (!orgConfig) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.organizationMailConfig', 'SMTP AUTH disabled tenant-wide');
  }
  if (orgConfig.smtpClientAuthenticationDisabled === true) {
    return {
      status: 'PASS',
      detail: 'Legacy SMTP AUTH is disabled tenant-wide.',
      evidence: { smtpClientAuthenticationDisabled: true },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Legacy SMTP AUTH is not disabled tenant-wide, leaving a non-Conditional-Access-aware authentication path available.',
    evidence: { smtpClientAuthenticationDisabled: orgConfig.smtpClientAuthenticationDisabled },
  };
}

// ---------------------------------------------------------------------------
// mailbox-auditing-not-bypassed
// ---------------------------------------------------------------------------

export function evaluateMailboxAuditingNotBypassed(signals: TenantCollectionResult): EvaluationOutcome {
  const bypassEntries = exoCompliance(signals)?.mailboxAuditBypass;
  // An empty array IS meaningful collected data (checked, found zero bypasses) — distinct from
  // `undefined` (not collected at all). Only the latter is UNKNOWN.
  if (bypassEntries === undefined) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.mailboxAuditBypass', 'Mailbox auditing not bypassed');
  }
  const enabledBypass = bypassEntries.filter((b) => b.auditBypassEnabled);
  if (enabledBypass.length === 0) {
    return {
      status: 'PASS',
      detail: 'No mailboxes have audit-bypass enabled.',
      evidence: { bypassEntryCount: bypassEntries.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${enabledBypass.length} mailbox(es) have audit-bypass enabled, silently suppressing their audit records.`,
    evidence: { bypassedMailboxes: enabledBypass.map((b) => b.identity) },
  };
}

// ---------------------------------------------------------------------------
// mailbox-auditing-enabled-tenant-wide
// ---------------------------------------------------------------------------

export function evaluateMailboxAuditingEnabledTenantWide(signals: TenantCollectionResult): EvaluationOutcome {
  const orgConfig = exoCompliance(signals)?.organizationMailConfig;
  if (!orgConfig) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.organizationMailConfig', 'Mailbox auditing enabled tenant-wide');
  }
  if (orgConfig.auditDisabled === false) {
    return {
      status: 'PASS',
      detail: 'Tenant-wide (per-mailbox) Exchange mailbox auditing is enabled.',
      evidence: { auditDisabled: false },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Tenant-wide (per-mailbox) Exchange mailbox auditing is disabled, suppressing per-mailbox audit record generation.',
    evidence: { auditDisabled: orgConfig.auditDisabled },
  };
}

// ---------------------------------------------------------------------------
// transport-rules-no-external-forwarding
// ---------------------------------------------------------------------------

export function evaluateTransportRulesNoExternalForwarding(signals: TenantCollectionResult): EvaluationOutcome {
  const transportRules = exoCompliance(signals)?.transportRules;
  if (!transportRules) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.transportRules', 'Transport rules no external forwarding');
  }
  const offendingRules = transportRules.filter((r) => r.state === 'Enabled' && r.isExternalForwardingRule);
  if (offendingRules.length === 0) {
    return {
      status: 'PASS',
      detail: 'No enabled transport rule auto-forwards or BCCs mail to external recipients.',
      evidence: { transportRuleCount: transportRules.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${offendingRules.length} enabled transport rule(s) auto-forward or BCC mail externally.`,
    evidence: { offendingRules: offendingRules.map((r) => ({ id: r.id, name: r.name })) },
  };
}

// ---------------------------------------------------------------------------
// remote-domain-auto-forward-disabled
// ---------------------------------------------------------------------------

function isDefaultRemoteDomain(domainName: string): boolean {
  return domainName === '*' || domainName.toLowerCase() === 'default';
}

export function evaluateRemoteDomainAutoForwardDisabled(signals: TenantCollectionResult): EvaluationOutcome {
  const remoteDomains = exoCompliance(signals)?.remoteDomains;
  if (!remoteDomains) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.remoteDomains', 'Remote domain auto-forward disabled');
  }
  const offending = remoteDomains.filter((d) => d.autoForwardEnabled);
  if (offending.length === 0) {
    return {
      status: 'PASS',
      detail: `No remote domain (of ${remoteDomains.length}) has automatic forwarding enabled.`,
      evidence: { remoteDomainCount: remoteDomains.length },
    };
  }
  const offendingDefault = offending.filter((d) => isDefaultRemoteDomain(d.domainName));
  return {
    status: 'FAIL',
    detail: offendingDefault.length > 0
      ? `The default remote domain allows automatic forwarding, along with ${offending.length - offendingDefault.length} other domain(s).`
      : `${offending.length} remote domain(s) allow automatic forwarding.`,
    evidence: { offendingDomains: offending.map((d) => d.domainName) },
  };
}

// ---------------------------------------------------------------------------
// mailbox-forwarding-external-blocked
//
// This control previously had no registered evaluator (it existed in the catalog with only
// `requiredSignals: ['secureScore']`, presumably intended to be inferred indirectly from a
// Secure Score control-improvement-action signal, but no such evaluator was ever implemented).
// We implement it directly here now that authoritative Exchange signals exist, reusing the same
// remoteDomains + transportRules checks as remote-domain-auto-forward-disabled /
// transport-rules-no-external-forwarding — both angles (transport rules AND remote domain
// auto-forward) must be clear for external auto-forwarding to be considered blocked. This is a
// strictly more direct/confident check than the old Secure-Score-inference approach the catalog
// description implied, so we treat it as superseding that in confidence (catalog's
// `requiredSignals` is updated to the direct PowerShell signals accordingly).
// ---------------------------------------------------------------------------

export function evaluateMailboxForwardingExternalBlocked(signals: TenantCollectionResult): EvaluationOutcome {
  const remoteDomains = exoCompliance(signals)?.remoteDomains;
  const transportRules = exoCompliance(signals)?.transportRules;
  if (!remoteDomains && !transportRules) {
    return missingSignalOutcome(
      signals,
      'exoTeams.exoCompliance.remoteDomains',
      'Mailbox forwarding to external domains blocked'
    );
  }

  const offendingRemoteDomains = (remoteDomains ?? []).filter((d) => d.autoForwardEnabled);
  const offendingTransportRules = (transportRules ?? []).filter(
    (r) => r.state === 'Enabled' && r.isExternalForwardingRule
  );

  if (offendingRemoteDomains.length === 0 && offendingTransportRules.length === 0) {
    if (!remoteDomains || !transportRules) {
      // One of the two contributing signals is present and clean, but the other wasn't
      // collected at all — we can't fully rule out an external-forwarding path via the
      // uncollected mechanism, so this is a partial (not full) pass.
      return {
        status: 'PARTIAL',
        detail:
          'No external-forwarding transport rules or remote-domain auto-forwarding were found among ' +
          'the collected signal(s), but one of the two contributing signals (remote domains, transport ' +
          'rules) was not collected this cycle, so this cannot be fully confirmed.',
        evidence: {
          remoteDomainsCollected: !!remoteDomains,
          transportRulesCollected: !!transportRules,
        },
      };
    }
    return {
      status: 'PASS',
      detail: 'No remote domain allows automatic forwarding and no enabled transport rule forwards/BCCs mail externally.',
      evidence: { remoteDomainCount: remoteDomains.length, transportRuleCount: transportRules.length },
    };
  }

  return {
    status: 'FAIL',
    detail:
      `${offendingRemoteDomains.length} remote domain(s) allow automatic forwarding and ` +
      `${offendingTransportRules.length} enabled transport rule(s) forward/BCC mail externally.`,
    evidence: {
      offendingRemoteDomains: offendingRemoteDomains.map((d) => d.domainName),
      offendingTransportRules: offendingTransportRules.map((r) => ({ id: r.id, name: r.name })),
    },
  };
}

// ---------------------------------------------------------------------------
// calendar-sharing-not-external
// ---------------------------------------------------------------------------

export function evaluateCalendarSharingNotExternal(signals: TenantCollectionResult): EvaluationOutcome {
  const sharingPolicies = exoCompliance(signals)?.sharingPolicies;
  if (!sharingPolicies) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.sharingPolicies', 'Calendar sharing not external');
  }
  const offending = sharingPolicies.filter((p) => p.sharesCalendarDetailsExternally);
  if (offending.length === 0) {
    return {
      status: 'PASS',
      detail: `No sharing policy (of ${sharingPolicies.length}) shares calendar details externally.`,
      evidence: { sharingPolicyCount: sharingPolicies.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${offending.length} sharing polic${offending.length === 1 ? 'y shares' : 'ies share'} calendar details with external domains/anonymous users.`,
    evidence: { offendingPolicies: offending.map((p) => ({ id: p.id, name: p.name })) },
  };
}

// ---------------------------------------------------------------------------
// spam-filter-policy-active
// ---------------------------------------------------------------------------

export function evaluateSpamFilterPolicyActive(signals: TenantCollectionResult): EvaluationOutcome {
  const policies = exoCompliance(signals)?.hostedContentFilterPolicies;
  if (!policies) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.hostedContentFilterPolicies', 'Spam filter policy active');
  }
  const active = policies.filter((p) => !p.isEffectivelyDisabled);
  if (active.length > 0) {
    return {
      status: 'PASS',
      detail: `${active.length} of ${policies.length} hosted content filter polic${policies.length === 1 ? 'y is' : 'ies are'} active.`,
      evidence: { activePolicyCount: active.length, totalPolicyCount: policies.length },
    };
  }
  return {
    status: 'FAIL',
    detail: policies.length === 0
      ? 'No hosted content filter (anti-spam) policy is configured.'
      : `All ${policies.length} hosted content filter polic${policies.length === 1 ? 'y is' : 'ies are'} effectively disabled.`,
    evidence: { totalPolicyCount: policies.length },
  };
}

// ---------------------------------------------------------------------------
// no-connection-filter-ip-allowlist
// ---------------------------------------------------------------------------

export function evaluateNoConnectionFilterIpAllowlist(signals: TenantCollectionResult): EvaluationOutcome {
  const policies = exoCompliance(signals)?.hostedConnectionFilterPolicies;
  if (!policies) {
    return missingSignalOutcome(
      signals,
      'exoTeams.exoCompliance.hostedConnectionFilterPolicies',
      'No connection filter IP allow-list'
    );
  }
  const withAllowlist = policies.filter((p) => p.ipAllowList.length > 0);
  if (withAllowlist.length === 0) {
    return {
      status: 'PASS',
      detail: `No hosted connection filter policy (of ${policies.length}) has IP allow-list entries.`,
      evidence: { policyCount: policies.length },
    };
  }
  return {
    status: 'FAIL',
    detail: `${withAllowlist.length} hosted connection filter polic${withAllowlist.length === 1 ? 'y has' : 'ies have'} non-empty IP allow-list entries, bypassing spam filtering for those IPs.`,
    evidence: {
      policiesWithAllowlist: withAllowlist.map((p) => ({ id: p.id, name: p.name, ipAllowListSize: p.ipAllowList.length })),
    },
  };
}

// ---------------------------------------------------------------------------
// anti-phishing-policy-hardened
// ---------------------------------------------------------------------------

export function evaluateAntiPhishingPolicyHardened(signals: TenantCollectionResult): EvaluationOutcome {
  const policies = exoCompliance(signals)?.antiPhishPolicies;
  if (!policies) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.antiPhishPolicies', 'Anti-phishing policy hardened');
  }
  if (policies.length === 0) {
    return {
      status: 'FAIL',
      detail: 'No anti-phish policy is configured.',
      evidence: { policyCount: 0 },
    };
  }
  // Check the default policy primarily, as instructed; fall back to the first policy if no
  // default is flagged (still evaluated the same way, just noted in the detail).
  const target = policies.find((p) => p.isDefault) ?? policies[0]!;
  const flags = [target.enableMailboxIntelligence, target.enableSpoofIntelligence, target.enableTargetedUserProtection];
  const enabledCount = flags.filter(Boolean).length;

  const usedFallback = !policies.some((p) => p.isDefault);
  const detailSuffix = usedFallback ? ' (no policy flagged as default; evaluated the first reported policy instead)' : '';

  if (enabledCount === 3) {
    return {
      status: 'PASS',
      detail: `The ${usedFallback ? 'evaluated' : 'default'} anti-phish policy has mailbox intelligence, spoof intelligence, and targeted user protection all enabled${detailSuffix}.`,
      evidence: { policyId: target.id, ...flagsEvidence(target) },
    };
  }
  if (enabledCount > 0) {
    return {
      status: 'PARTIAL',
      detail: `The ${usedFallback ? 'evaluated' : 'default'} anti-phish policy has ${enabledCount} of 3 hardening flags enabled${detailSuffix}.`,
      evidence: { policyId: target.id, ...flagsEvidence(target) },
    };
  }
  return {
    status: 'FAIL',
    detail: `The ${usedFallback ? 'evaluated' : 'default'} anti-phish policy has none of mailbox intelligence, spoof intelligence, or targeted user protection enabled${detailSuffix}.`,
    evidence: { policyId: target.id, ...flagsEvidence(target) },
  };
}

function flagsEvidence(p: {
  enableMailboxIntelligence: boolean;
  enableSpoofIntelligence: boolean;
  enableTargetedUserProtection: boolean;
}): Record<string, unknown> {
  return {
    enableMailboxIntelligence: p.enableMailboxIntelligence,
    enableSpoofIntelligence: p.enableSpoofIntelligence,
    enableTargetedUserProtection: p.enableTargetedUserProtection,
  };
}

// ---------------------------------------------------------------------------
// safe-attachments-enabled
// ---------------------------------------------------------------------------

const BLOCKING_ACTION_MARKERS = ['block'];
const WEAK_ACTION_MARKERS = ['allow', 'monitor'];

export function evaluateSafeAttachmentsEnabled(signals: TenantCollectionResult): EvaluationOutcome {
  const policies = exoCompliance(signals)?.safeAttachmentsPolicies;
  if (!policies) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.safeAttachmentsPolicies', 'Safe Attachments enabled');
  }
  if (policies.length === 0) {
    return {
      status: 'FAIL',
      detail: 'No Safe Attachments policy is configured.',
      evidence: { policyCount: 0 },
    };
  }
  const target = policies.find((p) => p.isDefault) ?? policies[0]!;
  if (!target.enabled) {
    return {
      status: 'FAIL',
      detail: 'The Safe Attachments policy is disabled.',
      evidence: { policyId: target.id, enabled: false, action: target.action },
    };
  }
  const actionLower = target.action.toLowerCase();
  if (BLOCKING_ACTION_MARKERS.some((m) => actionLower.includes(m))) {
    return {
      status: 'PASS',
      detail: `The Safe Attachments policy is enabled with a blocking action ("${target.action}").`,
      evidence: { policyId: target.id, enabled: true, action: target.action },
    };
  }
  if (WEAK_ACTION_MARKERS.some((m) => actionLower.includes(m))) {
    return {
      status: 'PARTIAL',
      detail: `The Safe Attachments policy is enabled but its action ("${target.action}") does not block delivery.`,
      evidence: { policyId: target.id, enabled: true, action: target.action },
    };
  }
  return {
    status: 'PARTIAL',
    detail: `The Safe Attachments policy is enabled with an unrecognized action ("${target.action}") that could not be confirmed as blocking.`,
    evidence: { policyId: target.id, enabled: true, action: target.action },
  };
}

// ---------------------------------------------------------------------------
// safe-links-enabled-all-surfaces
// ---------------------------------------------------------------------------

export function evaluateSafeLinksEnabledAllSurfaces(signals: TenantCollectionResult): EvaluationOutcome {
  const policies = exoCompliance(signals)?.safeLinksPolicies;
  if (!policies) {
    return missingSignalOutcome(signals, 'exoTeams.exoCompliance.safeLinksPolicies', 'Safe Links enabled all surfaces');
  }
  if (policies.length === 0) {
    return {
      status: 'FAIL',
      detail: 'No Safe Links policy is configured.',
      evidence: { policyCount: 0 },
    };
  }
  const target = policies.find((p) => p.isDefault) ?? policies[0]!;
  const flags = [target.enableSafeLinksForEmail, target.enableSafeLinksForTeams, target.enableSafeLinksForOffice];
  const enabledCount = flags.filter(Boolean).length;
  const evidence = {
    policyId: target.id,
    enableSafeLinksForEmail: target.enableSafeLinksForEmail,
    enableSafeLinksForTeams: target.enableSafeLinksForTeams,
    enableSafeLinksForOffice: target.enableSafeLinksForOffice,
  };

  if (enabledCount === 3) {
    return {
      status: 'PASS',
      detail: 'Safe Links is enabled for Email, Teams, and Office apps.',
      evidence,
    };
  }
  if (enabledCount > 0) {
    return {
      status: 'PARTIAL',
      detail: `Safe Links is enabled for ${enabledCount} of 3 surfaces (Email/Teams/Office).`,
      evidence,
    };
  }
  return {
    status: 'FAIL',
    detail: 'Safe Links is not enabled for any surface (Email, Teams, or Office apps).',
    evidence,
  };
}

// ---------------------------------------------------------------------------
// unified-audit-log-ingestion-verified
//
// The existing `audit-log-retention-enabled` control (catalog.ts) is described as covering both
// "retention" and "ingestion", but its only `requiredSignals` entry is `recentSignIns` and it has
// no registered evaluator — sign-in records only corroborate that sign-ins are happening, not
// that Unified Audit Log ingestion itself is enabled, so implementing it as a proxy for THIS
// control's authoritative signal would be a materially weaker/different check than its
// description promises. Rather than overload that id with a mismatched direct signal, this is
// added as a distinct new control (`unified-audit-log-ingestion-verified`) backed by the direct
// PowerShell signal, and `audit-log-retention-enabled` is intentionally left as-is (still
// evaluator-less/UNKNOWN-by-fallback) since fixing its indirect inference is out of scope here.
// ---------------------------------------------------------------------------

export function evaluateUnifiedAuditLogIngestionVerified(signals: TenantCollectionResult): EvaluationOutcome {
  const config = exoCompliance(signals)?.unifiedAuditLogConfig;
  if (!config) {
    return missingSignalOutcome(
      signals,
      'exoTeams.exoCompliance.unifiedAuditLogConfig',
      'Unified Audit Log ingestion verified'
    );
  }
  if (config.unifiedAuditLogIngestionEnabled === true) {
    return {
      status: 'PASS',
      detail: 'Unified Audit Log ingestion is directly verified as enabled.',
      evidence: { unifiedAuditLogIngestionEnabled: true },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Unified Audit Log ingestion is disabled, so tenant activity is not being recorded for investigation/detection.',
    evidence: { unifiedAuditLogIngestionEnabled: config.unifiedAuditLogIngestionEnabled },
  };
}

// ---------------------------------------------------------------------------
// teams-external-federation-restricted
// ---------------------------------------------------------------------------

export function evaluateTeamsExternalFederationRestricted(signals: TenantCollectionResult): EvaluationOutcome {
  const federationConfig = teams(signals)?.federationConfig;
  if (!federationConfig) {
    return missingSignalOutcome(signals, 'exoTeams.teams.federationConfig', 'Teams external federation restricted');
  }
  if (federationConfig.allowFederatedUsers === false) {
    return {
      status: 'PASS',
      detail: 'Teams external federation is disabled.',
      evidence: { allowFederatedUsers: false },
    };
  }
  if (federationConfig.allowedDomainsIsUnrestricted === false) {
    return {
      status: 'PARTIAL',
      detail: 'Teams external federation is allowed, but restricted to an explicit domain allow-list.',
      evidence: { allowFederatedUsers: true, allowedDomainsIsUnrestricted: false },
    };
  }
  return {
    status: 'FAIL',
    detail: 'Teams external federation is allowed with no domain restriction (unrestricted).',
    evidence: { allowFederatedUsers: true, allowedDomainsIsUnrestricted: true },
  };
}

// ---------------------------------------------------------------------------
// teams-anonymous-meeting-join-restricted / teams-meeting-recording-governed
// ---------------------------------------------------------------------------

/**
 * Picks the Global (tenant-default) Teams meeting policy. Matches an `id` of "Global"
 * case-insensitively (Teams PowerShell conventionally names the default policy "Global"); if no
 * policy matches that name, falls back to the first entry in the array and callers note this
 * assumption in their `detail` output, since we can't otherwise reliably identify the tenant
 * default from this shape alone.
 */
function findGlobalMeetingPolicy(
  policies: TeamsCollectionResult['meetingPolicies']
): { policy: NonNullable<TeamsCollectionResult['meetingPolicies']>[number]; usedFallback: boolean } | undefined {
  if (!policies || policies.length === 0) return undefined;
  const global = policies.find((p) => p.id.toLowerCase() === 'global');
  if (global) return { policy: global, usedFallback: false };
  return { policy: policies[0]!, usedFallback: true };
}

export function evaluateTeamsAnonymousMeetingJoinRestricted(signals: TenantCollectionResult): EvaluationOutcome {
  const meetingPolicies = teams(signals)?.meetingPolicies;
  if (!meetingPolicies) {
    return missingSignalOutcome(signals, 'exoTeams.teams.meetingPolicies', 'Teams anonymous meeting join restricted');
  }
  const found = findGlobalMeetingPolicy(meetingPolicies);
  if (!found) {
    return {
      status: 'UNKNOWN',
      detail: 'Teams anonymous meeting join could not be evaluated: no meeting policies were reported.',
      evidence: { policyCount: 0 },
    };
  }
  const { policy, usedFallback } = found;
  const fallbackNote = usedFallback
    ? ' (no policy named "Global" found; evaluated the first reported meeting policy instead)'
    : '';

  if (!policy.allowAnonymousUsersToJoinMeeting && !policy.allowAnonymousUsersToStartMeeting) {
    return {
      status: 'PASS',
      detail: `The Global Teams meeting policy blocks anonymous users from joining or starting meetings${fallbackNote}.`,
      evidence: {
        policyId: policy.id,
        allowAnonymousUsersToJoinMeeting: policy.allowAnonymousUsersToJoinMeeting,
        allowAnonymousUsersToStartMeeting: policy.allowAnonymousUsersToStartMeeting,
      },
    };
  }
  return {
    status: 'FAIL',
    detail: `The Global Teams meeting policy allows anonymous users to ${policy.allowAnonymousUsersToJoinMeeting ? 'join' : ''}${
      policy.allowAnonymousUsersToJoinMeeting && policy.allowAnonymousUsersToStartMeeting ? ' and ' : ''
    }${policy.allowAnonymousUsersToStartMeeting ? 'start' : ''} meetings${fallbackNote}.`,
    evidence: {
      policyId: policy.id,
      allowAnonymousUsersToJoinMeeting: policy.allowAnonymousUsersToJoinMeeting,
      allowAnonymousUsersToStartMeeting: policy.allowAnonymousUsersToStartMeeting,
    },
  };
}

export function evaluateTeamsMeetingRecordingGoverned(signals: TenantCollectionResult): EvaluationOutcome {
  const meetingPolicies = teams(signals)?.meetingPolicies;
  if (!meetingPolicies) {
    return missingSignalOutcome(signals, 'exoTeams.teams.meetingPolicies', 'Teams meeting recording governed');
  }
  const found = findGlobalMeetingPolicy(meetingPolicies);
  if (!found) {
    return {
      status: 'UNKNOWN',
      detail: 'Teams meeting recording governance could not be evaluated: no meeting policies were reported.',
      evidence: { policyCount: 0 },
    };
  }
  const { policy, usedFallback } = found;
  const fallbackNote = usedFallback
    ? ' (no policy named "Global" found; evaluated the first reported meeting policy instead)'
    : '';

  if (!policy.allowCloudRecording) {
    return {
      status: 'PASS',
      detail: `Cloud recording is disabled on the Global Teams meeting policy${fallbackNote}.`,
      evidence: { policyId: policy.id, allowCloudRecording: false },
    };
  }
  // Judgment call (see catalog description): recording itself isn't inherently insecure, so this
  // is a PARTIAL review flag rather than a FAIL.
  return {
    status: 'PARTIAL',
    detail: `Cloud recording is enabled on the Global Teams meeting policy${fallbackNote}; confirm this is a deliberate data-handling decision with an appropriate retention/access review.`,
    evidence: { policyId: policy.id, allowCloudRecording: true },
  };
}

// ---------------------------------------------------------------------------
// teams-external-access-restricted
// ---------------------------------------------------------------------------

export function evaluateTeamsExternalAccessRestricted(signals: TenantCollectionResult): EvaluationOutcome {
  const clientConfig = teams(signals)?.clientConfig;
  if (!clientConfig) {
    return missingSignalOutcome(signals, 'exoTeams.teams.clientConfig', 'Teams external access restricted');
  }
  const { allowExternalAccess, allowGuestUser } = clientConfig;

  if (!allowExternalAccess && !allowGuestUser) {
    return {
      status: 'PASS',
      detail: 'Teams external access and guest access are both disabled.',
      evidence: { allowExternalAccess, allowGuestUser },
    };
  }

  // Judgment call (see catalog description): both are legitimate collaboration features, not
  // clear-cut misconfigurations like the other controls in this file, so enabled values are
  // flagged PARTIAL for organizational review rather than FAIL. We reserve FAIL for cases we
  // can directly confirm are unsafe (e.g. paired with an unrestricted federation allow-list),
  // which this signal alone can't establish.
  const enabledFeatures = [
    allowExternalAccess ? 'external access' : null,
    allowGuestUser ? 'guest access' : null,
  ].filter((f): f is string => f !== null);

  return {
    status: 'PARTIAL',
    detail: `Teams ${enabledFeatures.join(' and ')} ${enabledFeatures.length === 1 ? 'is' : 'are'} enabled; confirm this matches the organization's intended external-collaboration posture.`,
    evidence: { allowExternalAccess, allowGuestUser },
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Maps control catalog ids to their evaluator. Keys here must line up with the
 * `id` fields used in `src/lib/controls/catalog.ts`. Controls without a
 * matching key fall back to an "UNKNOWN - no evaluator implemented" result in
 * engine.ts, so it's safe for the catalog to define more controls than are
 * listed here.
 */
// NOTE: these keys must match the `id` fields in src/lib/controls/catalog.ts exactly
// (the catalog and this registry were built concurrently by different agents, and
// the ids initially drifted apart — evaluateTenant looks up evaluators by
// CONTROL_CATALOG's actual `control.id`, not by these function/variable names).
export const EVALUATOR_REGISTRY: Record<string, Evaluator> = {
  'mfa-admin-roles-required': evaluateMfaForAdmins,
  'mfa-all-users-required': evaluateMfaForAllUsers,
  'legacy-authentication-blocked': evaluateLegacyAuthBlocked,
  'no-standing-privileged-roles': evaluatePrivilegedRolesNoStandingAccess,
  'high-risk-users-remediated': evaluateRiskyUsersAddressed,
  'secure-score-above-threshold': evaluateSecureScoreAboveThreshold,
  'guest-access-review-configured': evaluateGuestAccessReviewed,
  'admin-consent-workflow-required': evaluateAdminConsentWorkflowRequired,
  'security-defaults-or-ca-baseline-enabled': evaluateSecurityDefaultsOrCaBaseline,
  'weak-authentication-methods-disabled': evaluateWeakAuthMethodsDisabled,
  'authenticator-number-matching-required': evaluateAuthenticatorNumberMatching,
  'fido2-attestation-enforced': evaluateFido2AttestationEnforced,
  'phishing-resistant-mfa-required': evaluatePhishingResistantMfaRequired,
  'device-code-flow-blocked': evaluateDeviceCodeFlowBlocked,
  'managed-device-required-for-mfa-registration': evaluateManagedDeviceRequiredForMfaRegistration,
  'high-risk-users-blocked-by-ca': evaluateHighRiskUsersBlockedByCa,
  'high-risk-signins-blocked-by-ca': evaluateHighRiskSignInsBlockedByCa,
  'global-admin-count-in-range': evaluateGlobalAdminCountInRange,
  'user-app-registration-restricted': evaluateUserAppRegistrationRestricted,
  'user-consent-to-apps-restricted': evaluateUserConsentToAppsRestricted,
  'guest-user-restricted-role': evaluateGuestUserRestrictedRole,
  'guest-invites-restricted-to-admins': evaluateGuestInvitesRestrictedToAdmins,
  'password-never-expires-policy': evaluatePasswordNeverExpiresPolicy,
  'app-registration-credential-hygiene': evaluateAppRegistrationCredentialHygiene,
  'privileged-service-principal-no-owners': evaluatePrivilegedServicePrincipalNoOwners,
  'privileged-service-principal-no-client-secrets': evaluatePrivilegedServicePrincipalNoClientSecrets,
  'non-privileged-users-mfa-registered': evaluateNonPrivilegedUsersMfaRegistered,

  // Exchange Online / Security & Compliance / Microsoft Teams controls.
  'dkim-signing-enabled-all-domains': evaluateDkimSigningEnabledAllDomains,
  'dmarc-policy-reject': evaluateDmarcPolicyReject,
  'smtp-auth-disabled-tenant-wide': evaluateSmtpAuthDisabledTenantWide,
  'mailbox-auditing-not-bypassed': evaluateMailboxAuditingNotBypassed,
  'mailbox-auditing-enabled-tenant-wide': evaluateMailboxAuditingEnabledTenantWide,
  'transport-rules-no-external-forwarding': evaluateTransportRulesNoExternalForwarding,
  'remote-domain-auto-forward-disabled': evaluateRemoteDomainAutoForwardDisabled,
  'mailbox-forwarding-external-blocked': evaluateMailboxForwardingExternalBlocked,
  'calendar-sharing-not-external': evaluateCalendarSharingNotExternal,
  'spam-filter-policy-active': evaluateSpamFilterPolicyActive,
  'no-connection-filter-ip-allowlist': evaluateNoConnectionFilterIpAllowlist,
  'anti-phishing-policy-hardened': evaluateAntiPhishingPolicyHardened,
  'safe-attachments-enabled': evaluateSafeAttachmentsEnabled,
  'safe-links-enabled-all-surfaces': evaluateSafeLinksEnabledAllSurfaces,
  'unified-audit-log-ingestion-verified': evaluateUnifiedAuditLogIngestionVerified,
  'teams-external-federation-restricted': evaluateTeamsExternalFederationRestricted,
  'teams-anonymous-meeting-join-restricted': evaluateTeamsAnonymousMeetingJoinRestricted,
  'teams-meeting-recording-governed': evaluateTeamsMeetingRecordingGoverned,
  'teams-external-access-restricted': evaluateTeamsExternalAccessRestricted,
};
