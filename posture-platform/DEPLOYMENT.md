# Deploying posture-platform on Railway

This document covers deploying the three runtime pieces of this app — the Next.js
web app, the background collection worker, and Postgres — to
[Railway](https://railway.com), with git-based auto-deploy from this repo.

**Read this whole document before creating services.** The single most common
mistake is step 2 below (Root Directory) — get it wrong and builds fail or, worse,
silently build the wrong thing.

---

## 0. Repo layout reminder

This repo's root contains an unrelated static marketing site. The actual app lives
in the `posture-platform/` subdirectory and is a self-contained npm project (its
own `package.json`, `Dockerfile`, `railway.json`, etc., all directly under
`posture-platform/`, not the repo root). Every Railway service you create for this
app must be pointed at that subdirectory — see step 2.

There are **two** Dockerfiles in `posture-platform/`: `Dockerfile` (used by the
`web` service) and `Dockerfile.worker` (used by the `worker` service, which
additionally needs PowerShell 7 — see step 5).

---

## 1. Create the Railway project

1. In Railway, **New Project -> Deploy from GitHub repo**, select this repo.
2. Railway will create one service from the detected Dockerfile at the repo root.
   Rename it to `web` for clarity — you'll add `worker` and `Postgres` next.

## 2. Set "Root Directory" on every service (critical)

For **every** service you add for this app (`web`, `worker`), open the service ->
**Settings -> Source -> Root Directory** and set it to:

```
posture-platform
```

(Railway's current UI takes a path relative to the repo root, without a leading
slash — `posture-platform`, not `/posture-platform`. If your Railway version
insists on a leading slash, `/posture-platform` is equivalent.)

Without this, Railway will try to build from the repo root, where there is no
`Dockerfile`/`package.json` for this app (only the unrelated marketing site) —
the build will fail immediately, or worse, pick up the wrong files if the repo
root ever gains its own `Dockerfile`.

**Note on the config file path:** Railway's config-as-code file discovery does
**not** follow Root Directory — if you ever need to point a service at a custom
config path, it must be the full repo-relative path, e.g.
`posture-platform/railway.json`, not just `railway.json`. The included
`railway.json` (see step 4) is discovered automatically because it sits at the
root of the directory named by Root Directory.

## 3. Add Postgres

**New -> Database -> Add PostgreSQL** in the same project. Railway provisions a
Postgres instance and exposes a `DATABASE_URL`-shaped connection string as a
reference variable on that Postgres service (Railway names the variable
`DATABASE_URL` on the Postgres plugin itself).

Do **not** hand-copy the connection string. In each of your `web` and `worker`
services, set the environment variable:

```
DATABASE_URL=${{Postgres.DATABASE_URL}}
```

using Railway's variable reference syntax (adjust `Postgres` to whatever you
named the database service). This keeps the URL in sync automatically if
Railway ever rotates it, and matches what `prisma/schema.prisma` expects
(`datasource db { url = env("DATABASE_URL") }`).

## 4. Configure the `web` service

### Build / deploy config

`posture-platform/railway.json` is committed and picked up automatically once
Root Directory is set correctly (step 2). It sets:

- `build.builder: DOCKERFILE`, `build.dockerfilePath: Dockerfile`
- `deploy.startCommand: ./docker-entrypoint.sh server` — runs
  `prisma migrate deploy`, then starts the Next.js standalone server.
- `deploy.healthcheckPath: /api/health` — see step 8.
- `deploy.restartPolicyType: ON_FAILURE` (3 retries).

You don't need to change anything in the Railway dashboard for `web` beyond
environment variables (next) and, optionally, generating a public domain
(**Settings -> Networking -> Generate Domain**, or attach a custom domain).

### Environment variables (web)

Set these on the `web` service (values are illustrative — use your own secrets,
never commit them):

| Variable | Notes |
|---|---|
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` — see step 3. |
| `NODE_ENV` | `production` (the Dockerfile already sets this; only override if you know why). |
| `NEXTAUTH_URL` | **Must exactly match** the public URL this service is reached at — Railway's generated `*.up.railway.app` domain, or your custom domain, including `https://`. If you attach a custom domain later, update this and redeploy; a mismatch breaks NextAuth callback/redirect handling. See step 7. |
| `NEXTAUTH_SECRET` | Generate with `openssl rand -base64 32`. Required by NextAuth in production. |
| `AZURE_AD_CLIENT_ID` | Entra ID app registration used for portal login (staff/customer SSO) — see `.env.example` comments. |
| `AZURE_AD_CLIENT_SECRET` | Secret for the same app registration. |
| `AZURE_AD_TENANT_ID` | Tenant ID for the same app registration. |
| `ENFORCE_MFA_CLAIM` | Optional. Leave unset (warn-only) until you've confirmed via logs that Entra's `amr` claim is flowing correctly; see `src/lib/auth/README.md`. |
| `CREDENTIAL_KMS_KEY_ID` | **Mandatory in production.** See "KMS prerequisite" below. |
| `AZURE_KEY_VAULT_URL` | **Mandatory in production**, alongside `CREDENTIAL_KMS_KEY_ID` — both or neither. Base URL of the Key Vault instance, e.g. `https://<vault-name>.vault.azure.net/`. |
| `CREDENTIAL_KMS_KEY_VERSION` | Optional — pins a specific Key Vault key version. Leave unset in normal operation (see `.env.example`). |
| `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` | Required on Railway (an off-Azure environment) so `DefaultAzureCredential` can authenticate to Key Vault via a service principal, since Managed Identity isn't available outside Azure infrastructure. Distinct from the `AZURE_AD_*` portal-login vars above — see "KMS prerequisite" below. |
| `PLATFORM_MULTI_TENANT_APP_CLIENT_ID` | Platform-wide multi-tenant app registration used to build customer admin-consent onboarding links. |

Do **not** set `CREDENTIAL_DEV_DATA_KEY` in this (or any production) environment
— it is a local-development-only fallback and the app explicitly refuses to use
it when `NODE_ENV=production` (see `src/lib/crypto/envelope.ts`).

### KMS prerequisite (blocking for production credential handling)

`CREDENTIAL_KMS_KEY_ID` and `AZURE_KEY_VAULT_URL` must both be set (or neither —
there is no partial configuration) for `getKmsProvider()` to construct the real
`AzureKeyVaultKmsProvider` (see `src/lib/crypto/kms.ts`). If unset in
production, the app hard-refuses (`NotConfiguredKmsProvider`, which always
throws) rather than silently no-op'ing — any code path touching
`TenantCredential` encryption/decryption fails loudly by design until this is
configured.

Before setting these on Railway, an operator must complete the one-time Azure
Key Vault setup documented in `src/lib/crypto/README.md`: create a Key Vault
instance, create an RSA key (2048+ bits, `wrapKey`/`unwrapKey` operations
enabled), and grant the app's identity `wrapKey`/`unwrapKey`-only permissions on
that specific key (Key Vault Crypto User role, not broader vault access).

Since Railway is not Azure infrastructure, `DefaultAzureCredential` cannot use
Managed Identity here — you must create a service principal (`az ad sp
create-for-rbac` or equivalent) with the same narrowly-scoped `wrapKey`/
`unwrapKey` permission on the Key Vault key, and set `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` on the `web` and `worker` services so
`DefaultAzureCredential` picks it up automatically (no code change needed).

## 5. Configure the `worker` service

The worker (`src/worker/index.ts`) collects Graph signals per tenant on a
schedule (`COLLECTION_INTERVAL_CRON`, default `0 */6 * * *` — every 6 hours).
Two ways to run it on Railway; **recommendation: option A (Cron Schedule)**.

### Build image: `Dockerfile.worker`, not `Dockerfile` (important)

The worker now also runs PowerShell 7 (`pwsh`) to drive Exchange Online,
Security & Compliance, and Microsoft Teams PowerShell modules (see
`src/lib/powershell/README.md` for what that layer does — it's a separate,
concurrent effort from this deployment change; this document only covers
getting it deployed).

`pwsh` plus the `ExchangeOnlineManagement` and `MicrosoftTeams` PowerShell
Gallery modules add roughly 500MB-1GB to the image and noticeably lengthen
the build (an extra APT repo registration + package install, then a
PowerShell Gallery module install with a non-trivial dependency graph). The
`web` service never uses PowerShell, so forcing that cost onto its image
would be pure waste on every `web` deploy. Instead:

- `web` keeps building from `Dockerfile` (unchanged) — small, fast, no
  PowerShell.
- `worker` builds from **`Dockerfile.worker`** (new, committed alongside
  `Dockerfile` at `posture-platform/Dockerfile.worker`) — same Next.js
  build + Prisma client generation as `Dockerfile`, plus `pwsh` and the two
  Exchange/Teams modules baked into the final image layer at build time (not
  installed at container startup — this avoids the worker depending on
  PowerShell Gallery being reachable at 3am for a scheduled run).

**Docker has no mechanism for one Dockerfile to `FROM` a stage defined in a
different Dockerfile**, so `Dockerfile.worker` duplicates the `deps` and
`builder` stages from `Dockerfile` verbatim (same base image, same `npm ci` /
`npm run build` / `prisma generate` steps) rather than sharing them, and only
diverges in the final runtime stage where it installs `pwsh` + modules. The
practical effect: the Next.js app is built twice per deploy cycle (once for
each image) instead of once. This was accepted as the simplest, most
self-contained option; the alternative (build one shared base image, push it
to a registry, and have both Dockerfiles `FROM` that registry tag) would
avoid the duplicate build but adds a registry-push step and a
freshness/tagging problem (which base tag does a given commit correspond to)
that wasn't judged worth it for a Next.js build that takes well under a
minute. If build time or CI cost becomes a real problem later, that
shared-base approach is the next lever to pull. **If you change the `deps`
or `builder` stage in `Dockerfile`, make the same change in
`Dockerfile.worker`** — nothing enforces they stay in sync.

**A known risk worth checking on first deploy:** while building this feature, PowerShell
Gallery (`powershellgallery.com`) registration/module installation was unreliable in the
sandboxed environment this was developed in — likely a narrow, environment-specific network
restriction on PSGallery's OData protocol (plain HTTPS to other hosts, including
`packages.microsoft.com` for `pwsh` itself, worked fine). Railway's build infrastructure is a
different, standard cloud environment and most likely won't hit this, but if `Dockerfile.worker`'s
`Install-Module` step fails or hangs during a Railway build, that's the first thing to check —
Railway's build logs will show exactly where it fails. If it does turn out to be flaky, the next
lever to pull is pinning specific module versions (`-RequiredVersion`) and/or vendoring the
modules into the repo rather than fetching them at build time.

### Pointing the `worker` service at `Dockerfile.worker` on Railway

Railway's config-as-code file (`railway.json`) is discovered once per service
based on that service's Root Directory, and this repo's `railway.json` is
shared, single-service-shaped config (`build`/`deploy` objects, not a
`services` array) that both `web` and `worker` would otherwise pick up
identically. Rather than restructuring `railway.json` into a multi-service
array (a bigger, riskier change to a file `web` already depends on), the
worker's Dockerfile override is set **per-service in the Railway dashboard**,
which always takes precedence for that one setting:

1. Open the `worker` service -> **Settings -> Build**.
2. Find **Custom Dockerfile Path** (or set the service variable
   `RAILWAY_DOCKERFILE_PATH`, which is the config-as-code/variable-level
   equivalent of the same dashboard field) and set it to:
   ```
   Dockerfile.worker
   ```
   This is relative to the service's Root Directory (`posture-platform`, per
   step 2 above) — do **not** prefix it with `posture-platform/`.
3. Leave **Builder** as `Dockerfile` (it already is, inherited from detection)
   and leave everything else (Root Directory, Start Command, env vars) as
   already configured per this section.
4. Confirm on the next deploy that the build log shows `Dockerfile.worker`
   being used (Railway's build log prints the Dockerfile path near the top)
   and that the image build includes the `pwsh`/PowerShell Gallery install
   steps — if it doesn't, the override didn't take, and the service is still
   building from the default `Dockerfile`.

Do **not** make this change on the `web` service — it should keep building
from the default `Dockerfile` (no override needed; that's what `railway.json`
already specifies for it).

### Option A (recommended): Railway Cron Schedule + one-shot `worker:once`

Railway service settings include a **Cron Schedule** field: Railway starts the
service's container on the given schedule, runs its start command, and expects
the process to **exit** when the task is done (if it doesn't exit before the
next scheduled run, that run is skipped). This is a first-class, distinct
feature from Railway's "Background Worker" service type — Railway bills compute
only while the container is actually running, not between runs.

To support this without turning `src/worker/index.ts`'s normal behavior into a
breaking change, a minimal, additive `--once` CLI flag was added: it runs
exactly one collection cycle (loads tenants, evaluates + scores, writes a
snapshot) and calls `process.exit(0)`/`process.exit(1)`, instead of registering
a `node-cron` schedule and staying resident. The default (no flag) behavior is
untouched.

Setup:

1. Create a service from the same repo/image as `web` (**New -> GitHub Repo**,
   same repo). Set **Root Directory** to `posture-platform` (step 2).
2. **Settings -> Deploy -> Start Command**: `./docker-entrypoint.sh worker:once`
   (equivalently `npm run worker:once`, but the entrypoint script avoids
   running `prisma migrate deploy` a second time — see the Dockerfile/entrypoint
   comments).
3. **Settings -> Cron Schedule**: a standard 5-field crontab expression, e.g.
   `0 */6 * * *` to match the app's own default interval. Railway's minimum
   granularity is 5 minutes; schedules run in UTC.
4. Do **not** also set `COLLECTION_INTERVAL_CRON` as an env var here — that
   variable only affects the always-resident mode (Option B), not `--once`.
5. Do **not** give this service a public domain — it has no HTTP server and
   doesn't need one. It does need `DATABASE_URL` and whatever Graph API
   credentials the collection code reads (see `.env.example`) — copy the same
   env vars as `web` except `NEXTAUTH_*` (not used by the worker).
6. Leave **Healthcheck Path** unset for this service — it's a one-shot job, not
   a request-serving process; healthchecks are for `web` only (step 8).

Tradeoff: the Railway Cron Schedule contract requires the process to exit
promptly and cleanly, including closing DB connections/pools; if a future
change to `collectAndScoreTenant` introduces something that can hang (e.g. an
un-awaited background timer), a one-shot run could overrun into the next
scheduled tick and get skipped by Railway. The bounded-concurrency, all-tenants
cycle already used by `runCycle()` completes and returns today, so this is a
theoretical risk, not a known issue.

### Option B (alternative): Background Worker service, always-on

Instead of Cron Schedule, run the worker as a normal always-on Railway service
using its existing built-in scheduling:

1. Same service creation as above, but:
2. **Settings -> Deploy -> Start Command**: `./docker-entrypoint.sh worker`
   (equivalently `npm run worker`).
3. Do **not** set a Cron Schedule on this service — leave it unset so Railway
   treats it as a normal long-running service (a "Background Worker" in
   Railway's terminology: no exposed port, no public domain, but the container
   stays up continuously).
4. `COLLECTION_INTERVAL_CRON` env var now matters — it configures the
   in-process `node-cron` schedule inside `src/worker/index.ts`.

Tradeoff: you pay for a container that's up 24/7 even though it's idle between
runs (collection only happens every few hours by default), in exchange for one
less moving part (no `--once` semantics to reason about, and the process
handles its own scheduling exactly as it does today outside Railway). If your
collection interval were minutes rather than hours, this option would be the
better fit since Railway's Cron minimum granularity is 5 minutes.

**Either option builds from `Dockerfile.worker`** (see above) rather than the
same image as `web` — this is the one place the worker's setup now differs
from a "just change the Start Command" second service; everything else about
Option A/B below (Start Command, Cron Schedule, env vars) is unchanged.

### Per-tenant prerequisite for the new Exchange/Teams controls

Everything in steps 1-5 above (Graph-based collection) works for every
onboarded tenant exactly as before — nothing about the PowerShell layer
changes onboarding for existing, Graph-only controls, and no action is
required to keep those working.

The **new** Exchange Online / Security & Compliance / Microsoft Teams
controls (collected via `pwsh`, see `src/lib/powershell/README.md`) need
additional per-tenant setup beyond the Graph admin-consent flow in
`src/lib/graph/README.md`, because Exchange/Teams PowerShell cmdlets
authenticate and authorize differently than Graph application permissions:

1. The customer's app registration needs the **`Exchange.ManageAsApp`** API
   permission (Office 365 Exchange Online API), granted via admin consent —
   this is in addition to, not a replacement for, the Graph application scopes
   already listed in `src/lib/graph/README.md`.
2. The app registration's **service principal** must be assigned the
   **Exchange Administrator** and **Teams Administrator** Entra ID roles in
   the customer's tenant (Entra admin center -> Roles & administrators ->
   assign to the service principal, not to a user).

This is documented in full, including exact steps, in
`src/lib/powershell/README.md` — treat that file as authoritative for the
precise cmdlet-level requirements; this section only flags that the extra
setup exists and that it's a per-tenant, incremental step. The onboarding UI (`src/app/(onboarding)/onboarding/tenants/[tenantId]/credentials/page.tsx`)
surfaces this to the analyst as an additional, clearly-marked, non-blocking
note alongside the existing Graph admin-consent instructions — a tenant can
be fully onboarded and productive on Graph-based controls without ever doing
this, and can have it added later with no re-onboarding needed.

## 6. Migrations and seeding

- `prisma migrate deploy` runs automatically on every `web` service deploy, as
  the first step of `docker-entrypoint.sh server`, before the Next.js server
  starts. This applies pending migrations from `prisma/migrations/` and is
  safe to run on every restart/redeploy (a no-op if nothing is pending).
- `prisma migrate dev` is never invoked in this pipeline — it's interactive
  and dev-only, and does not belong in any deploy path.
- `npm run prisma:seed` (`prisma/seed.ts`) is **not** run automatically anywhere
  in this setup. Run it manually/on-demand when you actually need to seed data
  (e.g. the control catalog), via `railway run npm run prisma:seed` (Railway
  CLI, targets the `web` service's environment) or a one-off Railway CLI shell.
  Do not wire it into the container startup path — that would re-seed (or
  attempt to) on every restart.

## 6a. Bootstrapping the first SUPER_ADMIN

**This is a blocking step for a fresh deployment — do it once, right after
migrating (and, optionally, seeding the control catalog), before you try to
sign in.**

Sign-in is denied for every Entra ID principal unless a matching, active
`User` row already exists in Postgres (see `src/lib/auth/options.ts`
`lookupPortalUser`). Creating a `User` row via the admin UI/API in turn
requires an existing authenticated `SUPER_ADMIN` session
(`requireRole(['SUPER_ADMIN'])` — see
`src/app/api/admin/users/route-helpers.ts`). On a fresh database there are
zero `User` rows, so nobody can sign in to create the first one, and the admin
UI can't bootstrap itself. `prisma/bootstrap-admin.ts` (run via `npm run
bootstrap:admin`) exists solely to break this chicken-and-egg problem.

Run it manually/on-demand — the same way you'd run `prisma:seed` (Railway CLI
`railway run`, or a one-off shell), targeting the `web` service's environment:

```bash
railway run --service web \
  env BOOTSTRAP_ADMIN_EMAIL=you@yourcompany.com BOOTSTRAP_ORG_NAME="Your MSP Name" \
  npm run bootstrap:admin
```

(Locally: `BOOTSTRAP_ADMIN_EMAIL=you@yourcompany.com BOOTSTRAP_ORG_NAME="Your MSP Name" npm run bootstrap:admin`.)

What it does:

- Reads `BOOTSTRAP_ADMIN_EMAIL` (must exactly match the email address of the
  Entra ID account that will sign in — there are no passwords anywhere in this
  app) and `BOOTSTRAP_ORG_NAME` (the `Organization` to create if none yet
  exists with that name; an existing one with the same name is reused).
- Creates exactly one `User` row: the given email, `role: SUPER_ADMIN`,
  `isActive: true`.
- Is idempotent and **safe to leave wired up / re-run**: if a `User` row with
  `role: SUPER_ADMIN` already exists *anywhere* in the database (not just in
  the target organization), it refuses to create another one and exits
  cleanly, printing:
  > A SUPER_ADMIN already exists; refusing to bootstrap another one
  > automatically — use the admin UI or a manual database operation if you
  > need to add more admins.

  This is the key safety property: it's deliberately **not** automatic on
  every deploy (that would be a standing security risk — e.g. accidentally
  re-creating a known admin account after a real admin was intentionally
  removed), but it's also safe if `BOOTSTRAP_ADMIN_EMAIL` is accidentally left
  set in the environment across a redeploy, because the SUPER_ADMIN-exists
  check makes it a no-op after the first successful run.
- Fails loudly (non-zero exit) if `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ORG_NAME`
  are missing, or `BOOTSTRAP_ADMIN_EMAIL` isn't a plausible email shape, so a
  misconfigured invocation doesn't silently do nothing.

After this succeeds, sign in as that email via the portal's normal Entra ID
SSO login — you'll land with a `SUPER_ADMIN` session and can use **Admin ->
Users** to provision every other portal user (staff and customer viewers)
from there on. Do not add `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ORG_NAME` to your
permanent env var set on Railway — set them only for the single invocation
above (e.g. via `railway run env ... npm run bootstrap:admin`, as shown), then
they're no longer needed.

## 7. `NEXTAUTH_URL` and TLS

`NEXTAUTH_URL` must be the exact public URL of the `web` service, including
scheme:

- Using Railway's generated domain: `https://<your-service>.up.railway.app`
- Using a custom domain: `https://portal.yourdomain.com` (whatever you attach
  under **Settings -> Networking -> Custom Domain**)

Railway automatically provisions and renews TLS certificates for both its own
`*.up.railway.app` domains and any custom domain you attach (once its CNAME/DNS
record is verified) — no separate certificate management is required. If you
change domains later, update `NEXTAUTH_URL` and redeploy; a stale value breaks
NextAuth's OAuth redirect/callback validation.

## 8. Health check

`GET /api/health` (added at `src/app/api/health/route.ts`) runs
`prisma.$queryRaw\`SELECT 1\`` and returns:

- `200 { "status": "ok" }` if the query succeeds.
- `503 { "status": "unavailable" }` if it throws.

It requires no authentication (Railway's healthcheck prober can't authenticate)
and deliberately never includes error messages, stack traces, or connection
details in the response body — only server-side logs (via the existing Prisma
`log` config in `src/lib/db/client.ts`) carry that detail.

This is wired into `posture-platform/railway.json` as
`deploy.healthcheckPath: /api/health` for the `web` service only — Railway will
poll it after each deploy and only cut traffic over once it returns 200 (up to
`healthcheckTimeout` seconds, currently 30). Do **not** add a healthcheck path
to the `worker` service; it has no HTTP server.

## 9. Auto-deploy

Once each service's Root Directory and Start Command are set as above, Railway's
default GitHub integration behavior applies: pushes to the connected branch
(typically `main`) trigger a new build + deploy for every service watching that
branch, with zero extra config. Both `web` and `worker` (and Option A's Cron
Schedule invocations, which always use the latest successful deploy) pick up
new commits automatically.

If you want changes elsewhere in this monorepo (e.g. the unrelated marketing
site) to stop triggering rebuilds of `web`/`worker`, configure **Watch Paths**
on each service (**Settings -> Source -> Watch Paths**) scoped to
`posture-platform/**`.

## 10. Quick reference: env vars by service

| Variable | web | worker |
|---|---|---|
| `DATABASE_URL` | yes | yes |
| `NODE_ENV=production` | yes (Dockerfile default) | yes (Dockerfile default) |
| `NEXTAUTH_URL` | yes | no |
| `NEXTAUTH_SECRET` | yes | no |
| `AZURE_AD_CLIENT_ID` / `_SECRET` / `_TENANT_ID` | yes | no |
| `ENFORCE_MFA_CLAIM` | optional | no |
| `CREDENTIAL_KMS_KEY_ID` / `AZURE_KEY_VAULT_URL` | yes | yes (worker decrypts credentials to call Graph) |
| `CREDENTIAL_KMS_KEY_VERSION` | optional | optional |
| `AZURE_CLIENT_ID` / `_SECRET` / `_TENANT_ID` (service principal, for `DefaultAzureCredential`) | yes | yes |
| `PLATFORM_MULTI_TENANT_APP_CLIENT_ID` | yes | no |
| `COLLECTION_INTERVAL_CRON` | no | Option B only (ignored/unused under Option A `--once`) |

See `posture-platform/.env.example` for the authoritative, commented list of
every variable and what it's for. Any additional env vars the PowerShell/Exchange
layer needs (e.g. app-only auth for `Connect-ExchangeOnline`/`Connect-MicrosoftTeams`)
are documented in `src/lib/powershell/README.md`, not here — this table only
covers vars this deployment doc's own setup steps reference.

## 11. Build image summary: `Dockerfile` vs `Dockerfile.worker`

| | `web` | `worker` |
|---|---|---|
| Dockerfile | `Dockerfile` | `Dockerfile.worker` |
| Contains `pwsh` + Exchange/Teams PowerShell modules | no | yes |
| Approx. image size impact | baseline | +500MB-1GB |
| Configured via | `railway.json` (`build.dockerfilePath`, committed) | Railway dashboard per-service override (`Settings -> Build -> Custom Dockerfile Path`, or `RAILWAY_DOCKERFILE_PATH` variable) — see step 5 |

See step 5 for the full rationale and setup steps.
