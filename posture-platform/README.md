# myCIO Security Posture Platform

Multi-tenant Microsoft 365 security posture management platform for myCIO's managed
customers. Combines ISPM (identity/SaaS security posture management) and ITDR (identity
threat detection & response) signals from Microsoft Graph, maps them to NIST CSF 2.0 /
SP 800-53 controls, and tracks posture trends over time.

## Architecture

- **Next.js (App Router) + TypeScript** — portal UI and API routes.
- **PostgreSQL + Prisma** — multi-tenant data model; every query is scoped by tenant id.
- **Microsoft Graph (application permissions, client-credential flow)** — per-customer
  Entra ID app registrations grant this platform **read-only** access. See
  `src/lib/graph` for the exact scopes requested and why.
- **Background worker** — periodically pulls Graph signals per tenant, evaluates them
  against the control catalog, and writes a posture snapshot for trending.

## Security model (read this before touching auth or credential code)

1. **Least privilege by default.** The platform only ever requests the Graph
   application scopes listed in `src/types/domain.ts` (`REQUIRED_GRAPH_APPLICATION_SCOPES`).
   All of them are read-only. Any remediation/write action is a separate, explicit,
   per-tenant opt-in — never bundled into the default consent grant.
2. **Certificate auth preferred over client secrets** for customer tenant app
   registrations; if a secret is used, it is treated as short-lived and rotation is
   tracked.
3. **Credentials are envelope-encrypted at rest** (see `src/lib/crypto`) and are never
   logged, ever returned via API responses, or embedded in domain objects passed to the
   UI layer.
4. **Strict multi-tenant isolation.** All persistence access is scoped by `tenantId`;
   `SUPER_ADMIN`/`ANALYST` (MSP staff) may aggregate-report across every `Tenant` their
   `Organization` owns, but `CUSTOMER_VIEWER` (a customer's own staff) is additionally
   restricted to only the specific `Tenant`(s) explicitly granted via `TenantAccess` —
   see `src/lib/auth/rbac.ts`'s `getAccessibleTenantIds`/`canAccessTenant`. This exists
   because one Organization can own many unrelated customers' Tenant rows.
5. **Portal authentication** is always Entra ID SSO via NextAuth — there is no local
   password/account mechanism anywhere in this app. MFA is primarily enforced by an
   Entra ID Conditional Access policy on the portal's own app registration (an
   operational requirement, not code); a secondary, code-level defense-in-depth check
   of the `amr` claim exists (see `src/lib/auth/README.md`) but defaults to warn-only
   until an operator confirms the Entra-side configuration and opts into fail-closed via
   `ENFORCE_MFA_CLAIM=true`. RBAC roles: `SUPER_ADMIN`, `ANALYST`, `CUSTOMER_VIEWER`.
6. **Secure HTTP defaults** (CSP, HSTS, frame-ancestors none, etc.) are set globally in
   `next.config.mjs` — do not relax without a documented reason.
7. **All administrative actions are audit-logged** to an append-only audit table.

## Control coverage and the Exchange/Teams PowerShell gap

The control catalog (`src/lib/controls/catalog.ts`) currently has 35 controls, informed by
[Maester](https://github.com/maester365/maester) (a PowerShell/Pester M365 test framework
covering CISA's ScubaGear baseline plus EIDSCA) and [Prowler](https://prowler.com/prowler-for-microsoft-365)'s
M365 provider. Every control is traceable to a specific Maester test, CISA ScubaGear policy
id, or Prowler check name — see the source citation in each `ControlDefinition`'s evaluator.

**All 35 are collectible via Microsoft Graph application permissions alone** — the
client-credential auth flow this platform uses end-to-end. This was a deliberate scoping
decision, not an oversight: Maester and Prowler's own source confirms a clean split in
*their* architecture between Graph-only services (Entra ID, Intune, SharePoint admin
settings) and services that require a live Exchange Online / Security & Compliance /
Microsoft Teams PowerShell session (`connect_exchange_online()` in Prowler's own code) —
there is no Graph v1.0/beta equivalent for these today:

- **Mail flow / Exchange Online**: DKIM signing, DMARC record policy, transport rules,
  SMTP AUTH, mailbox audit logging/bypass, calendar sharing, shared-mailbox sign-in state
- **Microsoft Defender for Office 365**: anti-phishing/mailbox intelligence, Safe
  Attachments, Safe Links, malware/spam filter policies, ZAP for Teams
- **Microsoft Teams**: external federation, anonymous meeting join, external chat
  restrictions, meeting recording policy
- **Purview / Unified Audit Log**: direct verification of `UnifiedAuditLogIngestionEnabled`
  (this platform's existing `audit-log-retention-enabled` control infers audit activity
  indirectly from sign-in log presence rather than reading this flag directly, for exactly
  this reason)

Adding these would require a second, structurally different collector: an authenticated
remote PowerShell/REST session against Exchange Online and Teams (typically
certificate-based app-only auth, a *different* auth surface than the Graph client-credential
flow this platform already implements, with its own credential-storage and least-privilege
considerations). That's a deliberate, scoped follow-up, not a partial implementation
attempt — tracked, not silently dropped.

## Getting started

```bash
npm install
cp .env.example .env.local   # fill in real values, never commit
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed
BOOTSTRAP_ADMIN_EMAIL=you@yourcompany.com BOOTSTRAP_ORG_NAME="Your MSP Name" npm run bootstrap:admin
npm run dev
```

The `bootstrap:admin` step creates the first `SUPER_ADMIN` user so someone can
actually sign in and use the admin UI to provision everyone else afterward —
without it, there is no `User` row for anyone to sign in as (see
`src/lib/auth/options.ts` `lookupPortalUser`), a chicken-and-egg problem the
admin UI itself can't solve since it requires an existing SUPER_ADMIN session.
`BOOTSTRAP_ADMIN_EMAIL` must exactly match an email address that will sign in
via Entra ID SSO. It is safe to leave this command in your notes/scripts and
re-run it later — it refuses to do anything if a SUPER_ADMIN already exists.
See `DEPLOYMENT.md` ("Bootstrapping the first SUPER_ADMIN") for the full
details and production usage.
