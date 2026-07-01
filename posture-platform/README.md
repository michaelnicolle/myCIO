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
   there is no code path that queries across tenants except explicit cross-tenant
   aggregate reporting for the owning MSP organization.
5. **Portal authentication** uses Entra ID SSO via NextAuth with MFA enforced, plus
   RBAC (`SuperAdmin`, `Analyst`, `CustomerViewer`).
6. **Secure HTTP defaults** (CSP, HSTS, frame-ancestors none, etc.) are set globally in
   `next.config.mjs` — do not relax without a documented reason.
7. **All administrative actions are audit-logged** to an append-only audit table.

## Getting started

```bash
npm install
cp .env.example .env.local   # fill in real values, never commit
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed
npm run dev
```
