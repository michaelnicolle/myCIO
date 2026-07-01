# src/lib/graph

Microsoft Graph integration layer for posture-platform. This module authenticates against each
customer's Entra ID tenant using the OAuth2 **client-credentials** flow (application permissions
only — no signed-in user, no delegated permissions) and collects a fixed set of read-only
security signals used by the scoring engine.

## Files

| File | Responsibility |
| --- | --- |
| `authClient.ts` | Builds an authenticated `Client` from `@azure/identity` credentials (certificate preferred, secret as fallback) + retry middleware. Knows nothing about credential storage/encryption. |
| `rateLimiter.ts` | `RetryWithBackoffMiddleware` — exponential backoff with jitter, `Retry-After`-aware, capped attempts/total wait. Reusable Graph SDK `Middleware`. |
| `pagination.ts` | `fetchAllPages` — follows `@odata.nextLink` with a hard page cap. |
| `collectors.ts` | One function per signal, each validating the raw Graph response with zod before returning our strict `Graph*` type. |
| `index.ts` | `collectTenantSignals(entraTenantId, authConfig)` — runs all collectors in parallel, isolates per-collector failures into `result.errors`, assembles `TenantCollectionResult`. |

## Required Microsoft Graph application permissions

This platform requests exactly the scopes in `REQUIRED_GRAPH_APPLICATION_SCOPES`
(`src/types/domain.ts`) — nothing broader, and no write/remediation scopes. Every collector below
is read-only (`GET` only).

| Scope | Why it's needed | Used by |
| --- | --- | --- |
| `SecurityEvents.Read.All` | Read the tenant's Microsoft Secure Score and control scores. | `collectSecureScore` (`GET /security/secureScores`) |
| `IdentityRiskEvent.Read.All` | Read Identity Protection risk detections (individual risky sign-in/user events). | `collectRiskDetections` (`GET /identityProtection/riskDetections`) |
| `IdentityRiskyUser.Read.All` | Read the current risk state of users flagged by Identity Protection. | `collectRiskyUsers` (`GET /identityProtection/riskyUsers`) |
| `AuditLog.Read.All` | Read sign-in logs to observe recent authentication activity and conditional access outcomes. | `collectRecentSignIns` (`GET /auditLogs/signIns`) |
| `Policy.Read.All` | Read Conditional Access policy configuration (state, conditions, grant controls). | `collectConditionalAccessPolicies` (`GET /identity/conditionalAccess/policies`) |
| `RoleManagement.Read.Directory` | Read directory role assignments (who holds Global Administrator, etc.). | `collectPrivilegedRoleAssignments` (`GET /roleManagement/directory/roleAssignments`) |
| `Directory.Read.All` | Resolve the `principal` (user/servicePrincipal/group) and `roleDefinition` objects expanded on role assignments; also sufficient on its own for reading `/domains` (see note below — `Domain.Read.All` is requested too but is not strictly required). | `collectPrivilegedRoleAssignments` (`$expand=roleDefinition,principal`), `collectDomains` (`GET /domains`) |
| `User.Read.All` | Resolve user identity details (UPN, display name) referenced by risky users, risk detections, and sign-in events. | `collectRiskyUsers`, `collectRiskDetections`, `collectRecentSignIns` (indirectly, via user references in those payloads) |
| `Reports.Read.All` | Read per-user authentication method registration state (MFA/SSPR registration, methods registered). | `collectUserRegistrationDetails` (`GET /reports/authenticationMethods/userRegistrationDetails`) |
| `Application.Read.All` | Read app registration credential metadata (password/key credentials, for expiry and secret-sprawl hygiene checks) and service principal details/owners for privileged-role-holding service principals. | `collectApplications` (`GET /applications`), `collectPrivilegedServicePrincipals` (`GET /servicePrincipals/{id}`, `GET /servicePrincipals/{id}/owners`) |
| `Domain.Read.All` | Requested for domain password-policy reads, but **not actually required**: `GET /domains` with application permissions is satisfied by `Directory.Read.All` alone, which this platform already requests. `Domain.Read.All` is harmless (read-only, no broader access than `Directory.Read.All` already grants for this endpoint) but is not consumed as a hard dependency by any collector — kept in `REQUIRED_GRAPH_APPLICATION_SCOPES` for explicitness/documentation, not because `collectDomains` would fail without it. |
| `Policy.Read.All` (additional consumers) | Also backs the new tenant-wide policy singletons below, beyond Conditional Access. | `collectAuthorizationPolicy` (`GET /policies/authorizationPolicy`), `collectAuthenticationMethodsPolicy` (`GET /policies/authenticationMethodsPolicy`), `collectSecurityDefaultsPolicy` (`GET /policies/identitySecurityDefaultsEnforcementPolicy`), `collectAdminConsentRequestPolicy` (`GET /policies/adminConsentRequestPolicy`) |

All of the above are **application** (app-only) permissions, not delegated — they must be granted
via **admin consent** in the customer's tenant, since there is no signed-in user to prompt.

## Admin consent

A customer tenant admin grants this platform's app registration the permissions above by visiting:

```
https://login.microsoftonline.com/{tenant-id}/adminconsent?client_id={client-id}
```

Where:
- `{tenant-id}` is the customer's Entra ID (Azure AD) tenant GUID (or a verified domain).
- `{client-id}` is this platform's multi-tenant app registration's Application (client) ID.

The admin must be a Global Administrator (or a role with
`Microsoft.Directory/servicePrincipals/managePermissionGrants/allScopes` equivalent rights) in the
customer tenant. After consent, Microsoft redirects to the app registration's configured redirect
URI; the onboarding flow (built elsewhere in this repo) is responsible for confirming consent
succeeded before marking the tenant `ACTIVE`.

This module does not construct or handle that consent redirect itself — it only assumes that, by
the time `collectTenantSignals` is called for a tenant, admin consent for the scopes above has
already been granted. If it has not (or a scope was revoked), the affected collector(s) will fail
with a 403/`Authorization_RequestDenied`-style error, which `collectTenantSignals` captures into
`result.errors` without blocking collection of the other signals.

## Authentication: certificate vs. client secret

- **Certificate (`GraphCertificateAuthConfig`)** is the primary, preferred path. Pass the
  decrypted PEM certificate (+ private key) and, if applicable, its passphrase. The certificate's
  thumbprint is derived by the underlying MSAL client from the certificate itself — it is not a
  separate input.
- **Client secret (`GraphSecretAuthConfig`)** is a fallback path only, clearly marked as such in
  `authClient.ts`. New tenant onboardings should default to certificates; existing secret-based
  tenants should be migrated and the secret path phased out per-tenant as that migration
  completes.

Either way, **this module never sees encrypted credentials or knows how they're stored** — the
caller (onboarding/credential-management code elsewhere in the repo) is responsible for decryption
and must hand `createGraphClient` / `collectTenantSignals` plain, ready-to-use values. Credential
material is never logged, including in error paths — see `redactAuthConfig` and the error-wrapping
helpers in `authClient.ts` and `index.ts`.

## Rate limiting & retries

Every request made through a client returned by `createGraphClient` passes through
`RetryWithBackoffMiddleware` (`rateLimiter.ts`), which:

- Retries on HTTP 429, 503, and 504.
- Honors `Retry-After` (seconds or HTTP-date) when Graph provides it.
- Otherwise uses exponential backoff with full jitter.
- Is capped at 5 attempts and 60 seconds of total wait per request, regardless of caller
  configuration (`ABSOLUTE_MAX_RETRIES` / `ABSOLUTE_MAX_TOTAL_WAIT_MS`), so a persistently
  throttled or unhealthy tenant can never hang a collection cycle indefinitely.

## Pagination

Endpoints that can return multiple pages (`riskyUsers`, `riskDetections`, CA policies, role
assignments, sign-ins, domains, applications, user registration details) are followed via
`@odata.nextLink` by `fetchAllPages` (`pagination.ts`), up to a hard cap of pages
(`ABSOLUTE_MAX_PAGES = 50`, with `collectRecentSignIns` further constrained to 20 pages of 500,
and `collectApplications` to 20 pages of 500, to bound worst-case volume on very active/large
tenants).

`collectPrivilegedServicePrincipals` is the one exception to "paginate the collection endpoint":
it deliberately never calls `GET /servicePrincipals` over the whole tenant (which could return
tens of thousands of objects for a large customer). Instead it reuses the already-collected
`privilegedRoleAssignments` output (avoiding a second, expensive call to
`/roleManagement/directory/roleAssignments`), takes the distinct set of `servicePrincipal`
principal ids that hold a privileged role, and fans out one `GET /servicePrincipals/{id}` + one
`GET /servicePrincipals/{id}/owners` call per principal. That fan-out is capped at
`PRIVILEGED_SERVICE_PRINCIPALS_MAX_LOOKUPS = 200` distinct service principals per collection cycle
— comfortably above any realistic count of privileged-role-holding service principals, while still
bounding worst-case request volume; if the cap is hit, the excess principals are silently skipped
rather than failing the whole collector.

## Failure isolation

`collectTenantSignals` runs all collectors concurrently via `Promise.all` (each wrapped so a
rejection is caught individually) and never lets one collector's failure prevent the others from
completing. Missing permissions, a tenant having no Conditional Access policies configured, a
transient outage that exhausts retries, or a malformed response that fails zod validation, all
result in an entry pushed to `TenantCollectionResult.errors` (`{ signal, message }`) rather than
an exception from `collectTenantSignals` itself.

The one ordering exception: `privilegedRoleAssignments` is awaited before the rest of the
collectors start, because `collectPrivilegedServicePrincipals` needs its output as an input (see
"Pagination" above) rather than re-fetching it. If `privilegedRoleAssignments` fails, its error is
recorded as usual and `privilegedServicePrincipals` is skipped entirely (also recorded, effectively
a "dependency unavailable" case) — no other, unrelated collector is affected, and all of them still
run concurrently in the second `Promise.all`.
