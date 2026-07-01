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

**Either option uses the same Docker image as `web`** — nothing to build or
push separately; you're only changing the Start Command (and, for Option A,
setting Cron Schedule) on a second service.

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
every variable and what it's for.
