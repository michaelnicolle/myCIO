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
  conditions: Record<string, unknown>;
  grantControls?: { builtInControls: string[] } | null;
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
  errors?: Array<{ signal: string; message: string }>;
}
