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
  (`AZURE_AD_CLIENT_ID`) that requires MFA for all users, all sign-ins. **This
  is the primary, authoritative control.**
- Recommended: additionally require a compliant/managed device, and/or block
  legacy authentication, per your organization's baseline.
- Without this, NextAuth will happily accept single-factor sign-in. The
  application code in this directory cannot enforce Conditional Access itself,
  but it does include a secondary detection/enforcement layer (below)
  precisely because this Conditional Access policy is an operational step
  outside this codebase, and nothing prevents an operator from forgetting to
  configure it.

### Secondary layer: `amr` claim check (`ENFORCE_MFA_CLAIM`)

`src/lib/auth/options.ts` additionally inspects Entra ID's **Authentication
Methods References (`amr`) claim** on sign-in, as defense-in-depth in case the
Conditional Access policy above was never configured, was misconfigured, or
was scoped to the wrong app registration. **This is a secondary detection/
enforcement layer only — it does not replace Conditional Access.** If MFA
Conditional Access is never configured, sign-ins will simply never carry
`amr: ["mfa"]`, and depending on `ENFORCE_MFA_CLAIM` this will either warn
forever or deny every sign-in; it does not make Conditional Access optional.

#### (a) One-time Entra app registration change required for this to work at all

The `amr` claim is **not** included in an Entra ID ID token by default.
NextAuth (and this app) cannot see it unless you explicitly add it as an
**optional claim** on the **portal's** app registration (the one identified by
`AZURE_AD_CLIENT_ID`, not the platform's multi-tenant monitoring app
registration):

1. In the Azure/Entra portal, go to **App registrations** > select the portal
   login app registration (`AZURE_AD_CLIENT_ID`).
2. Go to **Token configuration**.
3. Click **Add optional claim**.
4. Token type: **ID**.
5. Select the **`amr`** claim from the list, then **Add**.
6. If prompted to also turn on the corresponding Graph permission, accept it
   (Microsoft sometimes offers this for certain claims; for `amr` it is
   typically not required, but follow the portal's prompt).
7. Save.

Until this is done, the `amr` claim will never be present on the ID token, and
this app cannot distinguish "Conditional Access MFA is not enforced" from
"the optional claim just isn't wired up yet" — which is exactly why the
default mode below is warn-only rather than fail-closed.

#### (b) Behavior

Controlled by the `ENFORCE_MFA_CLAIM` env var (see `.env.example`):

- **Unset / falsy (default).** Warn-only. On every sign-in where the `amr`
  claim is missing, or present but does not include `"mfa"`, a loud banner is
  logged via `console.warn` identifying the signing-in user's email address
  and stating that Conditional Access MFA may not be enforced. **Sign-in is
  still allowed.** This is the safe default: enabling fail-closed before the
  Entra-side optional-claim configuration in (a) is actually done would lock
  out every single user, since the claim would never be present for anyone.
- **`"true"` or `"1"`.** Fail-closed. On the same condition (claim missing, or
  present without `"mfa"`), sign-in is **denied** (the `signIn` callback
  returns `false`) and the reason is logged.
- **Claim present and includes `"mfa"`** (the expected/healthy state once
  Conditional Access MFA and the optional claim are both correctly
  configured): sign-in proceeds silently in either mode — no warning, no
  special logging.

This check runs in the `signIn` callback in `options.ts`, ahead of the
`lookupPortalUser` check (cheaper, no DB round-trip, so it fails fast), but
both must independently pass — a user with no provisioned portal `User` row is
still denied regardless of `amr`/MFA claim status, and vice versa.

#### (c) Recommended rollout

1. Deploy with `ENFORCE_MFA_CLAIM` **unset**.
2. Watch application logs for the warning banner across real sign-ins from
   real users (not just yourself) for a representative period. Confirm you
   see **no** warnings — i.e. the `amr` claim is flowing through correctly and
   contains `"mfa"` for legitimate sign-ins. If you see the warning
   unexpectedly often, first check whether the optional claim in (a) is
   actually configured before assuming Conditional Access itself is broken.
3. Only once you've confirmed the claim is flowing through correctly, set
   `ENFORCE_MFA_CLAIM=true` to move to fail-closed enforcement.

#### Implementation note

NextAuth v4's `AzureADProvider` only maps a handful of fields (`id`, `name`,
`email`, `image`) from the decoded ID token into the profile object it
normally returns — `amr` is not one of them. `options.ts` overrides the
provider's `profile()` callback to additionally preserve `amr` onto that
object. (NextAuth v4's OAuth callback handler also separately passes the full,
raw decoded ID token claims — including `amr`, when present — as the `profile`
argument of the `signIn` callback, independent of the provider's `profile()`
mapping; the `profile()` override is kept anyway as belt-and-suspenders so
`amr` isn't dropped for any other consumer of the provider's profile.)

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

**Signature note:** `requireRole` takes only `allowedRoles`, not a `request`
argument. NextAuth v4's `getServerSession(authOptions)` reads the session from
`next/headers` cookies internally in both Route Handlers and Server
Components under the App Router, so there is nothing for a route handler to
pass in — threading `request` through would be dead weight. This is a
deliberate deviation from a `requireRole(request, allowedRoles)` sketch.
