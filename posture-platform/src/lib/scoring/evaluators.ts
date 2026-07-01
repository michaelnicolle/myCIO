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
};
