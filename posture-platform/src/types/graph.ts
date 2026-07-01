/**
 * Typed shapes for the subset of Microsoft Graph responses this platform consumes.
 * Kept intentionally narrow (only fields we use) rather than mirroring full Graph schemas.
 */

export interface GraphSecureScore {
  id: string;
  createdDateTime: string;
  currentScore: number;
  maxScore: number;
  controlScores: Array<{
    controlName: string;
    score: number;
    controlCategory: string;
  }>;
}

export interface GraphRiskyUser {
  id: string;
  userPrincipalName: string;
  riskLevel: 'low' | 'medium' | 'high' | 'hidden' | 'none' | 'unknownFutureValue';
  riskState: 'none' | 'confirmedSafe' | 'remediated' | 'dismissed' | 'atRisk' | 'confirmedCompromised';
  riskLastUpdatedDateTime: string;
}

export interface GraphRiskDetection {
  id: string;
  userId: string;
  riskEventType: string;
  riskLevel: 'low' | 'medium' | 'high' | 'hidden' | 'none' | 'unknownFutureValue';
  detectedDateTime: string;
  activity: string;
}

export interface GraphConditionalAccessPolicy {
  id: string;
  displayName: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  /**
   * Loosely typed by design — CA `conditions` is a large, evolving Graph shape.
   * Evaluators that need specific fields (e.g. `userRiskLevels`, `signInRiskLevels`,
   * `clientAppTypes`, `authenticationFlows.transferMethods`) read them off this
   * bag with a local narrow cast rather than this file modeling every field.
   */
  conditions: Record<string, unknown>;
  grantControls?: {
    builtInControls: string[];
    /** Present when the policy grants access via an Authentication Strength (e.g. phishing-resistant MFA) rather than/in addition to builtInControls. */
    authenticationStrength?: { id: string; displayName?: string } | null;
  } | null;
}

export interface GraphDirectoryRoleAssignment {
  id: string;
  roleDefinitionId: string;
  roleName: string;
  principalId: string;
  principalType: 'user' | 'servicePrincipal' | 'group';
  isPrivileged: boolean;
}

export interface GraphSignInEvent {
  id: string;
  userPrincipalName: string;
  createdDateTime: string;
  isInteractive: boolean;
  clientAppUsed: string;
  conditionalAccessStatus: 'success' | 'failure' | 'notApplied' | 'unknownFutureValue';
  riskLevelDuringSignIn: string;
}

/** GET /policies/authorizationPolicy — tenant-wide user privilege defaults. */
export interface GraphAuthorizationPolicy {
  id: string;
  guestUserRoleId: string;
  allowInvitesFrom: 'none' | 'adminsAndGuestInviters' | 'adminsGuestInvitersAndAllMembers' | 'everyone';
  defaultUserRolePermissions?: {
    allowedToCreateApps?: boolean;
    permissionGrantPoliciesAssigned?: string[];
  } | null;
}

/** GET /policies/authenticationMethodsPolicy — per-method configuration (MFA hygiene). */
export interface GraphAuthenticationMethodsPolicy {
  id: string;
  authenticationMethodConfigurations: Array<{
    /** e.g. "Sms", "Voice", "Email", "MicrosoftAuthenticator", "Fido2". */
    id: string;
    state: 'enabled' | 'disabled';
    /** Present only on the MicrosoftAuthenticator configuration. */
    featureSettings?: {
      numberMatchingRequiredState?: { state: 'enabled' | 'disabled' };
      displayAppInformationRequiredState?: { state: 'enabled' | 'disabled' };
    };
    /** Present only on the Fido2 configuration. */
    isAttestationEnforced?: boolean;
  }>;
}

/** GET /policies/identitySecurityDefaultsEnforcementPolicy */
export interface GraphSecurityDefaultsPolicy {
  id: string;
  isEnabled: boolean;
}

/** GET /policies/adminConsentRequestPolicy */
export interface GraphAdminConsentRequestPolicy {
  id: string;
  isEnabled: boolean;
  notifyReviewers: boolean;
  requestDurationInDays: number;
  reviewers?: Array<Record<string, unknown>>;
}

/** GET /domains */
export interface GraphDomain {
  id: string;
  isVerified: boolean;
  isDefault: boolean;
  /** Null/undefined means "never expires" on many tenants' default config — evaluators must not treat absence as a failure by itself. */
  passwordValidityPeriodInDays?: number | null;
}

/** GET /applications — app registrations (not the same object as their service principal). */
export interface GraphApplication {
  id: string;
  appId: string;
  displayName: string;
  passwordCredentials: Array<{ keyId: string; displayName?: string | null; endDateTime?: string | null; startDateTime?: string | null }>;
  keyCredentials: Array<{ keyId: string; type?: string; endDateTime?: string | null; startDateTime?: string | null }>;
}

/** GET /servicePrincipals (+ /owners) — the sign-in/permissions identity of an app in this tenant. */
export interface GraphServicePrincipal {
  id: string;
  appId: string;
  displayName: string;
  servicePrincipalType: string;
  passwordCredentials: Array<{ keyId: string; endDateTime?: string | null }>;
  /** Ids of the service principal's owners (users or other service principals). Empty array means no owners. */
  ownerIds: string[];
}

/** One row from GET /reports/authenticationMethods/userRegistrationDetails */
export interface GraphUserRegistrationDetail {
  id: string;
  userPrincipalName: string;
  isMfaRegistered: boolean;
  isAdmin: boolean;
  methodsRegistered: string[];
}

/** Normalized bundle of everything a single collection cycle gathers for one tenant. */
export interface TenantCollectionResult {
  tenantId: string;
  collectedAt: string;
  secureScore?: GraphSecureScore;
  riskyUsers?: GraphRiskyUser[];
  riskDetections?: GraphRiskDetection[];
  conditionalAccessPolicies?: GraphConditionalAccessPolicy[];
  privilegedRoleAssignments?: GraphDirectoryRoleAssignment[];
  recentSignIns?: GraphSignInEvent[];
  authorizationPolicy?: GraphAuthorizationPolicy;
  authenticationMethodsPolicy?: GraphAuthenticationMethodsPolicy;
  securityDefaultsPolicy?: GraphSecurityDefaultsPolicy;
  adminConsentRequestPolicy?: GraphAdminConsentRequestPolicy;
  domains?: GraphDomain[];
  applications?: GraphApplication[];
  privilegedServicePrincipals?: GraphServicePrincipal[];
  userRegistrationDetails?: GraphUserRegistrationDetail[];
  errors?: Array<{ signal: string; message: string }>;
}
