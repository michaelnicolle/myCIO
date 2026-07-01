# Project Handoff — myCIO Security Posture Platform

Written 2026-07-01, at the point this project moved from the `mycio` monorepo
into its own repo (`michaelnicolle/m365-secposture`). Read this before making
changes — it captures decisions, known gaps, and bugs already found and fixed
so they don't get reintroduced.

## What this is

A multi-tenant Next.js/TypeScript app that monitors customer Microsoft 365
tenants for an MSP (myCIO), combining ISPM (identity/SaaS security posture
management) and ITDR (identity threat detection & response). It authenticates
to each customer tenant via a certificate-based Entra ID app registration
(client-credential flow), pulls security signals from Microsoft Graph and
(optionally) Exchange Online/Teams PowerShell, evaluates them against a
53-control catalog mapped to NIST CSF 2.0 / NIST 800-53 / CIS Microsoft 365
Benchmark, tracks posture and Microsoft Secure Score trends over time, and
surfaces findings through a portal with RBAC.

## Architecture

- **Next.js 14 (App Router) + TypeScript**, strict mode, secure-by-default
  headers (CSP/HSTS/frame-ancestors none) in `next.config.mjs`.
- **PostgreSQL + Prisma** — every tenant-scoped table carries a non-nullable
  `tenantId`/`organizationId`. See `prisma/schema.prisma`.
- **Two collector subsystems**, both authenticating with the SAME per-tenant
  certificate (stored once, envelope-encrypted):
  - `src/lib/graph/` — Microsoft Graph, application permissions,
    `@azure/identity` client-credential flow. Read-only scopes only (see
    `REQUIRED_GRAPH_APPLICATION_SCOPES` in `src/types/domain.ts`).
  - `src/lib/powershell/` — Exchange Online / Security & Compliance / Teams
    PowerShell, via a Node→`pwsh` child-process bridge, for signals Graph
    has no API for (DKIM/DMARC, transport rules, Defender policies, Teams
    federation, Unified Audit Log). **Not yet tested against a live
    tenant** — see "Known gaps" below.
- **`src/worker/`** — background collection worker (`collectAndScoreTenant`
  in `collectTenant.ts` is the orchestration entry point: decrypt credential
  → collect Graph signals → collect PowerShell signals (cert-auth tenants
  only) → evaluate 53 controls → derive findings → compute a posture
  snapshot → persist, all per tenant, on a schedule).
- **`src/lib/controls/catalog.ts` + `src/lib/scoring/evaluators.ts`** — the
  53 controls and their evaluator functions. Every control resolves to a
  registered evaluator; some are deliberately `UNKNOWN`-by-design where the
  data genuinely isn't collectible yet (documented per-evaluator, not a bug).
- **Auth**: Entra ID SSO only (NextAuth), no local passwords anywhere.
  RBAC roles `SUPER_ADMIN` / `ANALYST` / `CUSTOMER_VIEWER`. A `TenantAccess`
  join table scopes `CUSTOMER_VIEWER` to specific tenants (see "Bugs already
  fixed" below for why this exists).
- **Credential encryption**: AES-256-GCM envelope encryption
  (`src/lib/crypto/envelope.ts`), DEK wrapped via Azure Key Vault
  (`src/lib/crypto/kms.ts`'s `AzureKeyVaultKmsProvider`) — hard-refuses to
  start in production without a real KMS key configured.
- **Deployment**: Railway-targeted. `Dockerfile` (web, lean) +
  `Dockerfile.worker` (worker, +PowerShell 7 and EXO/Teams modules baked in
  at build time). Full runbook in `DEPLOYMENT.md`.

## Current state (all committed, typecheck/lint/build clean as of handoff)

- 53 controls, all with registered evaluators.
- Microsoft Secure Score tracked as a first-class feature: per-control
  breakdown persisted (`SecureScoreControlResult`), trend chart + ranked
  outstanding-controls table on the tenant detail page, and a summary badge
  on the fleet-wide Overview page.
- Admin UI (`/admin/users`) for creating portal users, changing roles,
  granting/revoking `TenantAccess`.
- `npm run bootstrap:admin` solves the chicken-and-egg first-SUPER_ADMIN
  problem on a fresh deploy.
- Railway deployment config (Dockerfiles, `railway.json`, `DEPLOYMENT.md`)
  believed complete but **never actually deployed/tested against a real
  Railway project**.

## Known gaps — do these before/soon after going to production

1. **PowerShell/Exchange/Teams subsystem is unverified against a live
   tenant.** Module installation (`ExchangeOnlineManagement`,
   `MicrosoftTeams`) was blocked by a network restriction in the sandbox
   this was built in. The code is reviewed and syntax-validated but not
   runtime-tested. See `src/lib/powershell/README.md`'s verification-status
   section. Test this against a real customer tenant before relying on its
   19 controls.
2. **3 evaluators are `UNKNOWN`-by-design**, not bugs:
   `privileged-role-activation-requires-approval` (needs PIM
   `roleManagement/directory/roleManagementPolicies` data, not collected),
   `privileged-role-assignment-drift-detected` (needs stateful cross-cycle
   diffing the evaluator layer doesn't do), `inactive-account-review` (needs
   `/users?$select=signInActivity`, not collected — the current
   `recentSignIns` collector only pulls a 24-48h window). Each is documented
   in-code with exactly what signal would close the gap.
3. **No automated test suite or CI.** `vitest` is a dependency but there are
   zero test files. Everything so far has been verified via manual
   typecheck/lint/build + hand-written throwaway smoke scripts against a
   live Postgres instance (not committed). This is real, recurring risk —
   several integration bugs (see below) were only caught by manual review,
   not automated checks.
4. **No remediation-tracking workflow.** Findings surface in the dashboard
   but there's no attached guidance, owner, due date, or guided-fix
   workflow — this is the gap vs. commercial tools like CloudCapsule if that
   comparison matters to you.
5. **KMS requires real setup before any real tenant credential works.** The
   `AzureKeyVaultKmsProvider` is real code, but needs an actual Azure Key
   Vault instance + RSA key + service-principal access before it functions —
   see `src/lib/crypto/README.md` and `DEPLOYMENT.md`'s KMS section.
6. **MFA enforcement is primarily operational, not code.** The app's `amr`
   claim check (`src/lib/auth/options.ts`) is a secondary, warn-by-default
   defense-in-depth layer — the authoritative control is an Entra
   Conditional Access policy on the portal's own app registration, which is
   a manual setup step, not something this codebase can verify for you.

## Bugs already found and fixed (context so they aren't reintroduced)

These were all caught by manual review during development, not by tests —
reinforcing why item 3 above matters:

- **Cross-tenant data leak**: `CUSTOMER_VIEWER` accounts were scoped only by
  MSP organization, so one customer's viewer could see a *different*
  customer's findings. Fixed with the `TenantAccess` join table
  (fail-closed: zero grants = zero visibility by default).
- **Scoring evaluator registry drift**: catalog control ids and evaluator
  registry keys were built by different people/passes and drifted apart —
  5 evaluators were silently dead (always `UNKNOWN`) until caught.
- **Missing `wrappedDataKey`/`kmsProvider` columns**: credentials were being
  encrypted but the wrapped data-encryption key was never persisted,
  meaning nothing could ever be decrypted again.
- **KMS key-rotation bug**: `AzureKeyVaultKmsProvider.unwrapKey` was using
  whichever Key Vault key version the process was configured with instead
  of the version actually recorded on each encrypted blob — rotating the
  vault key would have permanently broken decryption of every
  previously-encrypted credential.
- **Self-role-change footgun**: a `SUPER_ADMIN` could change their own role
  (unlike deactivation, which was blocked), risking an org with zero admins.
- **Onboarding form mislabeled its own cert field**: labeled "private key
  (PEM)" but every consumer (Graph auth, and now the PowerShell bridge)
  requires the combined certificate+key PEM. Fixed the label/placeholder.
- **No SUPER_ADMIN bootstrap path**: a fresh deploy had zero `User` rows and
  no way to create the first one (admin UI requires an existing
  `SUPER_ADMIN` session). Fixed with `prisma/bootstrap-admin.ts`.

## Suggested next steps, roughly in priority order

1. Finish the Railway deploy for real: create the project, follow
   `DEPLOYMENT.md` step by step, actually provision a Key Vault + service
   principal, run migrate + seed + bootstrap-admin, sign in, onboard one
   real test tenant.
2. Test the PowerShell/EXO/Teams subsystem against that real tenant; fix
   whatever cmdlet/parameter assumptions turn out wrong (see the honest
   caveats in `src/lib/powershell/README.md`).
3. Add an automated test suite (start with the scoring evaluators — they're
   pure functions, cheap to test — and the crypto round-trip) and wire up
   CI.
4. Decide whether the remediation-tracking workstream is worth building
   (CloudCapsule-parity gap) or out of scope for now.

## Prompt for the new session

See the accompanying message — paste that as your first message in a new
Claude Code session scoped to `michaelnicolle/m365-secposture`.
