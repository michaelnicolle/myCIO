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

import type { TenantCollectionResult, GraphConditionalAccessPolicy } from '@/types/graph';
import type { ControlStatus } from '@/types/domain';

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
};
