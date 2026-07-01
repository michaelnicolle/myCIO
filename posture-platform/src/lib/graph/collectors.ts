/**
 * One collector function per security signal this platform monitors. Every collector:
 *  - Calls exactly the Graph endpoint(s) documented in src/lib/graph/README.md.
 *  - Is satisfiable entirely by REQUIRED_GRAPH_APPLICATION_SCOPES (read-only; no write/remediation
 *    calls anywhere in this module).
 *  - Validates the raw Graph response shape with zod before casting to our strict domain type,
 *    since this is the point where external, untrusted-shape data crosses into our system.
 *  - Handles `@odata.nextLink` pagination where the endpoint can return multiple pages, capped at
 *    a sane max page count (see pagination.ts).
 *
 * Collectors intentionally throw on failure (missing permission, malformed response, network
 * error, etc.) rather than swallowing errors — it is the orchestrator's job (index.ts) to decide
 * how to handle a single collector failing without blocking the others.
 */

import type { Client } from '@microsoft/microsoft-graph-client';
import { z } from 'zod';

import type {
  GraphAdminConsentRequestPolicy,
  GraphApplication,
  GraphAuthenticationMethodsPolicy,
  GraphAuthorizationPolicy,
  GraphConditionalAccessPolicy,
  GraphDirectoryRoleAssignment,
  GraphDomain,
  GraphRiskDetection,
  GraphRiskyUser,
  GraphSecureScore,
  GraphSecurityDefaultsPolicy,
  GraphServicePrincipal,
  GraphSignInEvent,
  GraphUserRegistrationDetail,
} from '@/types/graph';
import { fetchAllPages } from './pagination';

// ---------------------------------------------------------------------------------------------
// Well-known privileged Entra ID role template IDs.
// Source: Microsoft's documented built-in role template IDs, which are stable GUIDs across all
// tenants (https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference).
// This list is deliberately conservative and favors flagging a superset of "clearly privileged"
// roles over trying to be exhaustive; expand it if the scoring engine needs finer granularity.
// ---------------------------------------------------------------------------------------------
export const PRIVILEGED_ROLE_TEMPLATE_IDS: ReadonlySet<string> = new Set([
  '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
  'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
  '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
  '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
  '729827e3-9c14-49f7-bb1b-9608f156bbb8', // Helpdesk Administrator
  'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', // Conditional Access Administrator
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
  '966707d0-3269-4727-9be2-8c3a10f19b9d', // Password Administrator
  'c4e39bd9-1100-46d3-8c65-fb160da0071f', // Authentication Administrator
  '158c047a-c907-4556-b7ef-446551a6b5f7', // Cloud Application Administrator
  'cf1c38e5-3621-4004-a7cb-879624dced7c', // Application Administrator
  'b0f54661-2d74-4c50-afa3-1ec803f12efe', // Billing Administrator
]);

/**
 * IMPORTANT: verify this list against the live tenant's actual role definitions before relying on
 * it for anything beyond advisory flagging. Role template IDs are stable and documented by
 * Microsoft (see README.md "Privileged role identification" section for the reference link), but
 * this module deliberately does not fetch /roleManagement/directory/roleDefinitions to cross-check
 * template IDs at runtime, to keep this a pure additive `$expand` on the assignments call.
 *
 * As defense in depth against a stale/incomplete ID list, we also match on the well-known,
 * case-insensitive display names of the same roles (resolved via `$expand=roleDefinition`) — a
 * role counts as privileged if EITHER its template ID or its display name matches.
 */
const PRIVILEGED_ROLE_DISPLAY_NAMES: ReadonlySet<string> = new Set(
  [
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Helpdesk Administrator',
    'User Administrator',
    'Conditional Access Administrator',
    'Privileged Authentication Administrator',
    'Password Administrator',
    'Authentication Administrator',
    'Cloud Application Administrator',
    'Application Administrator',
    'Billing Administrator',
  ].map((name) => name.toLowerCase()),
);

function isPrivilegedRole(templateId: string, displayName: string | undefined): boolean {
  if (PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateId)) return true;
  if (displayName && PRIVILEGED_ROLE_DISPLAY_NAMES.has(displayName.toLowerCase())) return true;
  return false;
}

const SECURE_SCORES_PATH = '/security/secureScores';
const RISKY_USERS_PATH = '/identityProtection/riskyUsers';
const RISK_DETECTIONS_PATH = '/identityProtection/riskDetections';
const CONDITIONAL_ACCESS_POLICIES_PATH = '/identity/conditionalAccess/policies';
const ROLE_ASSIGNMENTS_PATH = '/roleManagement/directory/roleAssignments';
const SIGN_INS_PATH = '/auditLogs/signIns';
const AUTHORIZATION_POLICY_PATH = '/policies/authorizationPolicy';
const AUTHENTICATION_METHODS_POLICY_PATH = '/policies/authenticationMethodsPolicy';
const SECURITY_DEFAULTS_POLICY_PATH = '/policies/identitySecurityDefaultsEnforcementPolicy';
const ADMIN_CONSENT_REQUEST_POLICY_PATH = '/policies/adminConsentRequestPolicy';
const DOMAINS_PATH = '/domains';
const APPLICATIONS_PATH = '/applications';
const SERVICE_PRINCIPALS_PATH = '/servicePrincipals';
const USER_REGISTRATION_DETAILS_PATH = '/reports/authenticationMethods/userRegistrationDetails';

const RISK_DETECTION_WINDOW_DAYS = 30;
const SIGN_IN_WINDOW_HOURS = 48;

// Per-endpoint page sizes, chosen conservatively within (or below) each endpoint's documented
// max $top to avoid Graph silently clamping or rejecting the request. Identity Protection and
// role-management collections are typically small per tenant; sign-ins can be large, hence the
// smaller page size but larger page-count cap.
const RISKY_USERS_PAGE_SIZE = 500;
const RISK_DETECTIONS_PAGE_SIZE = 500;
const CONDITIONAL_ACCESS_POLICIES_PAGE_SIZE = 200;
const ROLE_ASSIGNMENTS_PAGE_SIZE = 500;
const SIGN_IN_PAGE_SIZE = 500;
const SIGN_IN_MAX_PAGES = 20; // 20 * 500 = up to 10,000 sign-ins per collection cycle.
const DOMAINS_PAGE_SIZE = 100;
const APPLICATIONS_PAGE_SIZE = 500;
const APPLICATIONS_MAX_PAGES = 20; // 20 * 500 = up to 10,000 app registrations per collection cycle.
const USER_REGISTRATION_DETAILS_PAGE_SIZE = 500;
// Hard cap on individual GET /servicePrincipals/{id} (+ /owners) fan-out calls per collection
// cycle. Scoped to privileged-role-holding service principals only (never "every SP in the
// tenant"), but still bounded defensively in case an unusually large number of privileged role
// assignments resolve to service principal principals.
const PRIVILEGED_SERVICE_PRINCIPALS_MAX_LOOKUPS = 200;

function isoHoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function isoDaysAgo(days: number): string {
  return isoHoursAgo(days * 24);
}

// ---------------------------------------------------------------------------------------------
// Zod schemas for the raw Graph response shapes we consume. Deliberately permissive on fields we
// don't use (Graph adds fields over time) but strict on the fields we depend on.
// ---------------------------------------------------------------------------------------------

const riskLevelSchema = z.enum(['low', 'medium', 'high', 'hidden', 'none', 'unknownFutureValue']);

const secureScoreControlSchema = z.object({
  controlName: z.string(),
  score: z.number(),
  controlCategory: z.string(),
});

const secureScoreSchema = z
  .object({
    id: z.string(),
    createdDateTime: z.string(),
    currentScore: z.number(),
    maxScore: z.number(),
    controlScores: z.array(secureScoreControlSchema).default([]),
  })
  .passthrough();

const secureScoreCollectionSchema = z.object({
  value: z.array(secureScoreSchema),
});

const riskyUserSchema = z
  .object({
    id: z.string(),
    userPrincipalName: z.string(),
    riskLevel: riskLevelSchema,
    riskState: z.enum(['none', 'confirmedSafe', 'remediated', 'dismissed', 'atRisk', 'confirmedCompromised']),
    riskLastUpdatedDateTime: z.string(),
  })
  .passthrough();

const riskDetectionSchema = z
  .object({
    id: z.string(),
    userId: z.string(),
    riskEventType: z.string(),
    riskLevel: riskLevelSchema,
    detectedDateTime: z.string(),
    activity: z.string(),
  })
  .passthrough();

const conditionalAccessPolicySchema = z
  .object({
    id: z.string(),
    displayName: z.string(),
    state: z.enum(['enabled', 'disabled', 'enabledForReportingButNotEnforced']),
    conditions: z.record(z.unknown()).default({}),
    grantControls: z
      .object({ builtInControls: z.array(z.string()) })
      .nullish(),
  })
  .passthrough();

const roleAssignmentSchema = z
  .object({
    id: z.string(),
    roleDefinitionId: z.string(),
    principalId: z.string(),
    principalOrganizationId: z.string().optional(),
    roleDefinition: z
      .object({
        displayName: z.string().optional(),
        templateId: z.string().optional(),
      })
      .optional(),
    principal: z
      .object({
        '@odata.type': z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

const signInSchema = z
  .object({
    id: z.string(),
    userPrincipalName: z.string(),
    createdDateTime: z.string(),
    isInteractive: z.boolean(),
    clientAppUsed: z.string(),
    conditionalAccessStatus: z.enum(['success', 'failure', 'notApplied', 'unknownFutureValue']),
    riskLevelDuringSignIn: z.string(),
  })
  .passthrough();

const authorizationPolicySchema = z
  .object({
    id: z.string(),
    guestUserRoleId: z.string(),
    allowInvitesFrom: z.enum(['none', 'adminsAndGuestInviters', 'adminsGuestInvitersAndAllMembers', 'everyone']),
    defaultUserRolePermissions: z
      .object({
        allowedToCreateApps: z.boolean().optional(),
        permissionGrantPoliciesAssigned: z.array(z.string()).optional(),
      })
      .nullish(),
  })
  .passthrough();

const enabledDisabledStateSchema = z.object({ state: z.enum(['enabled', 'disabled']) });

const authenticationMethodConfigurationSchema = z
  .object({
    id: z.string(),
    state: z.enum(['enabled', 'disabled']),
    featureSettings: z
      .object({
        numberMatchingRequiredState: enabledDisabledStateSchema.optional(),
        displayAppInformationRequiredState: enabledDisabledStateSchema.optional(),
      })
      .passthrough()
      .optional(),
    isAttestationEnforced: z.boolean().optional(),
  })
  .passthrough();

const authenticationMethodsPolicySchema = z
  .object({
    id: z.string(),
    authenticationMethodConfigurations: z.array(authenticationMethodConfigurationSchema).default([]),
  })
  .passthrough();

const securityDefaultsPolicySchema = z
  .object({
    id: z.string(),
    isEnabled: z.boolean(),
  })
  .passthrough();

const adminConsentRequestPolicySchema = z
  .object({
    id: z.string(),
    isEnabled: z.boolean(),
    notifyReviewers: z.boolean(),
    requestDurationInDays: z.number(),
    reviewers: z.array(z.record(z.unknown())).optional(),
  })
  .passthrough();

const domainSchema = z
  .object({
    id: z.string(),
    isVerified: z.boolean(),
    isDefault: z.boolean(),
    passwordValidityPeriodInDays: z.number().nullish(),
  })
  .passthrough();

const credentialSchema = z
  .object({
    keyId: z.string(),
    displayName: z.string().nullish(),
    endDateTime: z.string().nullish(),
    startDateTime: z.string().nullish(),
  })
  .passthrough();

const keyCredentialSchema = z
  .object({
    keyId: z.string(),
    type: z.string().optional(),
    endDateTime: z.string().nullish(),
    startDateTime: z.string().nullish(),
  })
  .passthrough();

const applicationSchema = z
  .object({
    id: z.string(),
    appId: z.string(),
    displayName: z.string(),
    passwordCredentials: z.array(credentialSchema).default([]),
    keyCredentials: z.array(keyCredentialSchema).default([]),
  })
  .passthrough();

const servicePrincipalSchema = z
  .object({
    id: z.string(),
    appId: z.string(),
    displayName: z.string(),
    servicePrincipalType: z.string(),
    passwordCredentials: z.array(z.object({ keyId: z.string(), endDateTime: z.string().nullish() }).passthrough()).default([]),
  })
  .passthrough();

const servicePrincipalOwnerSchema = z.object({ id: z.string() }).passthrough();

const userRegistrationDetailSchema = z
  .object({
    id: z.string(),
    userPrincipalName: z.string(),
    isMfaRegistered: z.boolean(),
    isAdmin: z.boolean(),
    methodsRegistered: z.array(z.string()).default([]),
  })
  .passthrough();

/**
 * Secure score: GET /security/secureScores (latest).
 * Requires: SecurityEvents.Read.All
 */
export async function collectSecureScore(client: Client): Promise<GraphSecureScore | undefined> {
  const raw = await client.api(SECURE_SCORES_PATH).top(1).get();
  const parsed = secureScoreCollectionSchema.parse(raw);
  const latest = parsed.value[0];
  return latest;
}

/**
 * Risky users: GET /identityProtection/riskyUsers.
 * Requires: IdentityRiskyUser.Read.All
 */
export async function collectRiskyUsers(client: Client): Promise<GraphRiskyUser[]> {
  const initialRequest = client.api(RISKY_USERS_PATH).top(RISKY_USERS_PAGE_SIZE);
  const rawItems = await fetchAllPages(client, initialRequest, {});
  return rawItems.map((item) => riskyUserSchema.parse(item));
}

/**
 * Risk detections: GET /identityProtection/riskDetections, filtered to the last 30 days.
 * Requires: IdentityRiskEvent.Read.All
 */
export async function collectRiskDetections(client: Client): Promise<GraphRiskDetection[]> {
  const since = isoDaysAgo(RISK_DETECTION_WINDOW_DAYS);
  const initialRequest = client
    .api(RISK_DETECTIONS_PATH)
    .filter(`detectedDateTime ge ${since}`)
    .top(RISK_DETECTIONS_PAGE_SIZE);
  const rawItems = await fetchAllPages(client, initialRequest, {});
  return rawItems.map((item) => riskDetectionSchema.parse(item));
}

/**
 * Conditional access policies: GET /identity/conditionalAccess/policies.
 * Requires: Policy.Read.All
 */
export async function collectConditionalAccessPolicies(client: Client): Promise<GraphConditionalAccessPolicy[]> {
  const initialRequest = client.api(CONDITIONAL_ACCESS_POLICIES_PATH).top(CONDITIONAL_ACCESS_POLICIES_PAGE_SIZE);
  const rawItems = await fetchAllPages(client, initialRequest, {});
  return rawItems.map((item) => {
    const parsed = conditionalAccessPolicySchema.parse(item);
    return {
      ...parsed,
      grantControls: parsed.grantControls ?? null,
    };
  });
}

function classifyPrincipalType(principal: { '@odata.type'?: string } | undefined): GraphDirectoryRoleAssignment['principalType'] {
  const odataType = principal?.['@odata.type'] ?? '';
  if (odataType.includes('servicePrincipal')) return 'servicePrincipal';
  if (odataType.includes('group')) return 'group';
  return 'user';
}

/**
 * Privileged role assignments: GET /roleManagement/directory/roleAssignments, expanding
 * roleDefinition and principal so we can resolve a human-readable role name, the principal type,
 * and flag well-known privileged roles.
 * Requires: RoleManagement.Read.Directory (role/assignment data), Directory.Read.All (resolving
 * principal details on expand).
 */
export async function collectPrivilegedRoleAssignments(client: Client): Promise<GraphDirectoryRoleAssignment[]> {
  const initialRequest = client
    .api(ROLE_ASSIGNMENTS_PATH)
    .expand('roleDefinition,principal')
    .top(ROLE_ASSIGNMENTS_PAGE_SIZE);
  const rawItems = await fetchAllPages(client, initialRequest, {});

  return rawItems.map((item) => {
    const parsed = roleAssignmentSchema.parse(item);
    const templateId = parsed.roleDefinition?.templateId ?? parsed.roleDefinitionId;
    const roleName = parsed.roleDefinition?.displayName ?? 'Unknown role';
    return {
      id: parsed.id,
      roleDefinitionId: parsed.roleDefinitionId,
      roleName,
      principalId: parsed.principalId,
      principalType: classifyPrincipalType(parsed.principal),
      isPrivileged: isPrivilegedRole(templateId, parsed.roleDefinition?.displayName),
    };
  });
}

/**
 * Recent sign-ins: GET /auditLogs/signIns, filtered to the last 48 hours, paged with a sane cap.
 * Requires: AuditLog.Read.All
 */
export async function collectRecentSignIns(client: Client): Promise<GraphSignInEvent[]> {
  const since = isoHoursAgo(SIGN_IN_WINDOW_HOURS);
  const initialRequest = client
    .api(SIGN_INS_PATH)
    .filter(`createdDateTime ge ${since}`)
    .top(SIGN_IN_PAGE_SIZE);
  const rawItems = await fetchAllPages(client, initialRequest, { maxPages: SIGN_IN_MAX_PAGES });
  return rawItems.map((item) => signInSchema.parse(item));
}
