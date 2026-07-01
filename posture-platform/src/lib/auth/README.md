# src/lib/auth

Portal authentication (NextAuth v4, Entra ID / Azure AD provider) and the
application's RBAC guard. See the root `README.md` "Security model" section
first — this directory implements items 5 and (partially) 7 of that model.

## Session cookie posture

NextAuth v4 already defaults session cookies to `httpOnly: true`,
`sameSite: 'lax'`, and `secure: true` whenever it infers an HTTPS deployment.
We do not rely on that inference: `src/lib/auth/options.ts` sets these
explicitly on the `sessionToken` cookie, and uses the `__Secure-` cookie name
prefix in production, which browsers refuse to accept over plain HTTP or
without the `Secure` attribute — this makes a misconfiguration fail closed
rather than silently downgrading.

## Session lifetime

`maxAge` is set to **8 hours** (`SESSION_MAX_AGE_SECONDS` in `options.ts`).
This is deliberately short for a product that surfaces customer tenant
security/identity data. There is no "remember me" / long-lived session option.

## MFA / step-up authentication — operational requirement, not code

NextAuth's Azure AD provider performs an OAuth2/OIDC authorization-code
exchange against the **portal's own** Entra ID app registration
(`AZURE_AD_CLIENT_ID` / `AZURE_AD_TENANT_ID`). NextAuth has no mechanism to
require MFA or evaluate device/location/risk signals during that exchange —
that enforcement has to happen upstream, inside Entra ID itself, via
**Conditional Access policies scoped to the portal's app registration**.

**Operational requirement (must be configured in the Entra ID tenant that owns
the portal app registration, not in this codebase):**

- A Conditional Access policy targeting the portal's app registration
  (`AZURE_AD_CLIENT_ID`) that requires MFA for all users, all sign-ins.
- Recommended: additionally require a compliant/managed device, and/or block
  legacy authentication, per your organization's baseline.
- Without this, NextAuth will happily accept single-factor sign-in — the
  application code in this directory cannot detect or refuse that on its own.

## Role model

`Role = 'SUPER_ADMIN' | 'ANALYST' | 'CUSTOMER_VIEWER'`, mirroring the Prisma
`UserRole` enum. A signed-in Entra ID identity is mapped to a portal `User`
row (and therefore a role + `organizationId`) by email lookup in the `signIn`
and `jwt` callbacks in `options.ts`. **Sign-in is denied outright** if no
active `User` row exists for the email — there is no default/implicit role,
and provisioning a portal user (and picking their role) is an explicit admin
action outside of NextAuth.

## Authorization guard

Use `requireRole(allowedRoles)` from `src/lib/auth/rbac.ts` in route handlers
and server components:

```ts
import { requireRole } from '@/lib/auth/rbac';

const session = await requireRole(['ANALYST', 'SUPER_ADMIN']);
```

It throws `UnauthenticatedError` (no session) or `ForbiddenError` (wrong role)
rather than returning a falsy value, so a caller cannot forget to check a
boolean. Callers are expected to catch these, respond with 401/403, and — for
sensitive actions (tenant credential view/create/rotate) — still call
`writeAuditLog` for the denied attempt (see `src/lib/audit/log.ts`).

`getAuthorizedSession()` returns `null` instead of throwing; use it only when
you need the actor identity to log a denial without wanting the helper itself
to throw (rare — most call sites should use `requireRole`).
