# src/lib/powershell

A bridge from this Node.js/TypeScript app to Exchange Online, Security & Compliance, and
Microsoft Teams PowerShell, collecting security-configuration signals that Microsoft
Graph has no API surface for — confirmed by prior research: there is no Graph v1.0/beta
equivalent for DKIM signing config, DMARC records, mail transport rules, Defender for
Office 365 policies, Teams federation/meeting/messaging policies, etc. Everything in this
module produces `ExoComplianceCollectionResult` / `TeamsCollectionResult`
(`src/types/exoTeams.ts`), a sibling to `TenantCollectionResult` (`src/types/graph.ts`)
but explicitly *not* Graph-sourced.

> **Honest status check**: this subsystem has been syntax-checked and type-checked, but
> **has NOT been run against a live Exchange Online / Security & Compliance / Teams
> tenant**. The target PowerShell Gallery modules
> (`ExchangeOnlineManagement`, `MicrosoftTeams`) could not be installed in the authoring
> sandbox (PSGallery registration failed — appears to be a proxy/network restriction
> specific to the PowerShell Gallery's OData protocol; NuGet/npm worked fine). See
> "Verification status" below for exactly what was and wasn't confirmed before this is
> used in production.

## Files

| File | Responsibility |
| --- | --- |
| `bridge.ts` | `runPowerShellCollector<T>(scriptRelativePath, authConfig, timeoutMs)` — writes the certificate/key to a fresh temp dir, spawns `pwsh -File <script>` with `child_process.spawn` (never `exec`), enforces the timeout, parses stdout as JSON, and **unconditionally deletes the temp dir** in a `finally` block. |
| `collectExoCompliance.ts` | `collectExoComplianceSignals(authConfig)` — thin orchestrator calling `runPowerShellCollector` against `scripts/Collect-ExoComplianceSignals.ps1` (180s timeout). Never throws; a connection failure degrades to `{ collectedAt, errors: [...] }`. |
| `collectTeams.ts` | `collectTeamsSignals(authConfig)` — same pattern against `scripts/Collect-TeamsSignals.ps1` (120s timeout). |
| `scripts/Collect-ExoComplianceSignals.ps1` | Connects to Exchange Online (and, best-effort, Security & Compliance via `Connect-IPPSSession`) and collects DKIM, DMARC, transport rules, remote domains, org mail config, mailbox audit bypass, sharing policies, Defender for Office 365 policies (hosted content/connection filter, anti-phish, Safe Attachments, Safe Links), and unified audit log ingestion state. |
| `scripts/Collect-TeamsSignals.ps1` | Connects to Microsoft Teams PowerShell and collects tenant federation config, meeting policies, messaging policies, and client config. |

## Credential reuse model

**No new credential storage is introduced.** This module reuses the exact same
per-tenant certificate already stored (encrypted at rest, see `src/lib/crypto/envelope.ts`)
and used for Microsoft Graph app-only authentication
(`GraphCertificateAuthConfig` in `src/lib/graph/authClient.ts`). The same certificate,
already granted to the app registration for Graph scopes, is additionally granted the
Exchange/Teams permissions below and then handed — already decrypted, by the caller — to
`runPowerShellCollector` in exactly the shape Graph auth already uses:

```ts
interface GraphCertificateAuthConfig {
  kind: 'certificate';
  entraTenantId: string;
  clientId: string;
  certificatePem: string;       // combined cert + private key PEM, same as Graph's ClientCertificateCredential expects
  certificatePassword?: string; // optional, if the private key is itself encrypted
}
```

There is no separate "PowerShell credential" type, no separate encryption path, and no
separate onboarding flow for storing it — only an *additional permission/role grant* on
the same app registration (see below).

## Additional one-time customer setup required

Beyond the existing Graph admin-consent flow (`src/lib/graph/README.md`), a customer's
**Global Administrator** must, once per tenant, before these collectors will connect
successfully:

1. **Grant the app registration the `Exchange.ManageAsApp` API permission** — this is an
   **Office 365 Exchange Online** API permission (Application type), **not** a Microsoft
   Graph permission — and grant admin consent for it. This is what allows the app to
   request tokens scoped to Exchange Online / Security & Compliance PowerShell at all.
2. **Assign the app's service principal the `Exchange Administrator` Entra ID role** —
   required for the EXO and Security & Compliance cmdlets used by
   `Collect-ExoComplianceSignals.ps1` (RBAC in Exchange Online is enforced separately from
   the OAuth scope — a valid token without this role still gets 403s from the cmdlets).
3. **Assign the app's service principal the `Teams Administrator` Entra ID role** —
   required for `Collect-TeamsSignals.ps1`.

If any of these are missing (not yet granted, later revoked, or the certificate has
expired), the affected collector's `Connect-*` call fails and the *entire* script exits 0
with a single `errors: [{ signal: 'connection', message: '...' }]` entry — this is a
**graceful degradation**, not a hard failure. `collectExoComplianceSignals` /
`collectTeamsSignals` on the Node side never throw for this case; they return that same
degraded result shape so a missing permission grant for one tenant never blocks
collection for other tenants or other signal sources (Graph collection is entirely
unaffected).

## Security design of the bridge

`runPowerShellCollector` (`bridge.ts`) is the only place certificate/key material touches
disk in this subsystem, and it is built around one non-negotiable guarantee: **the temp
directory is always deleted**, regardless of success, thrown error, or a killed-on-timeout
child process.

1. **Fresh, unpredictable temp directory per call** — `fs.mkdtemp(path.join(os.tmpdir(),
   'posture-ps-bridge-'))` creates a directory with a random suffix; nothing before this
   call knows the path.
2. **Certificate and private key are split into two separate files**, `cert.pem` and
   `key.pem` (see `splitCombinedPem` — the same combined-PEM convention
   `@azure/identity`'s `ClientCertificateCredential` already expects from `authClient.ts`
   is parsed by regex into its `CERTIFICATE` and `PRIVATE KEY`/`ENCRYPTED PRIVATE
   KEY`/`RSA PRIVATE KEY`/`EC PRIVATE KEY` blocks). Each file is written with mode
   `0o600` — owner read/write only.
3. **The private key password (if the key is itself encrypted), if present, is passed via
   an environment variable (`PSBRIDGE_KEY_PASSWORD`) to the child process, not a CLI
   argument.** Rationale documented in `bridge.ts`: CLI arguments are visible via
   `ps aux` / `/proc/[pid]/cmdline`-style process listings; environment variables passed
   directly to a child are not exposed that way. This is **not** a complete solution —
   env vars are still readable via `/proc/[pid]/environ` by the same OS user (or root) —
   and the code comments say so explicitly rather than claiming a stronger guarantee than
   is actually true.
4. **`child_process.spawn` with an argument array, never `exec`** — avoids any shell
   interpretation of arguments (paths, GUIDs), eliminating shell-injection risk even
   though the expected inputs are well-formed GUIDs/file paths.
5. **Hard timeout enforcement** — `SIGTERM` first, escalating to `SIGKILL` after a grace
   period if the process hasn't exited.
6. **`try/finally` around the entire spawn+wait, with the `finally` unconditionally
   calling `fs.rm(tempDir, { recursive: true, force: true })`.** This is the primary
   control against leaking key material to disk — it does not depend on the PowerShell
   script's own (best-effort) cleanup, and it runs whether the script succeeded, threw, or
   was killed for exceeding `timeoutMs`.
7. **Nothing is ever logged that could contain secret material.** `certificatePem`,
   `certificatePassword`, and temp file *contents* are never passed to `console.*`,
   thrown `Error` messages, or the PowerShell scripts' own stdout/stderr. stderr from the
   child process is logged via `console.warn` (prefixed `[powershell:bridge]`) purely as
   diagnostic noise and is **never** parsed as data and never echoed back inside a thrown
   error — only a truncated snippet of the actually-received *stdout* is included in a
   JSON-parse-failure error, and stderr is excluded from that error entirely.
8. **Both PowerShell scripts follow the equivalent discipline on their side**: they never
   `Write-Output`/`Write-Host` certificate or key contents, accept the key password only
   via the `PSBRIDGE_KEY_PASSWORD` env var (never a `-KeyPassword` parameter), and only
   ever emit the single final JSON line as their designed stdout output.

### Teams authentication: in-memory certificate, not a cert-store import

`Collect-TeamsSignals.ps1` connects via `Connect-MicrosoftTeams -Certificate
<X509Certificate2> -ApplicationId <id> -TenantId <id>` — the **in-memory certificate
object** form (the module's "ServicePrincipalCertificate" parameter set), **not**
`-CertificateThumbprint` (which requires the certificate to already be imported into a
persistent OS certificate store, e.g. `Cert:\CurrentUser\My`, keyed only by thumbprint).
This was a design decision point per the task brief: research during authoring (Microsoft
Learn + community sources, since the module itself could not be installed to introspect)
indicates `-Certificate` accepting an in-memory object **is supported** by the
`MicrosoftTeams` PowerShell module (reintroduced around module version 4.7.1-preview per
sources reviewed), so the temporary-cert-store-import fallback described in the task brief
(import to `Cert:\CurrentUser\My`, use the thumbprint, then always remove it in
`finally`/`trap`) was **not implemented**, since it should not be necessary. If a
production run against the deployed module version finds `-Certificate` unsupported (e.g.
an older module version pinned in the runtime environment), that fallback is the
documented next step — and if implemented, it must carry the exact same
always-clean-up-even-on-error guarantee this bridge already applies to its temp
directory.

## Failure isolation

Both PowerShell scripts follow the same principle as `runCollector` in
`src/lib/graph/index.ts`, just implemented inside the script instead of in TypeScript
(since each script is a single child-process invocation from Node's point of view): every
individual `Get-*`/`Get-Cs*` call is wrapped in its own `try/catch`, appending
`{ signal, message }` to the result's `errors` array on failure rather than aborting the
script. A total connection failure (bad/expired cert, permission/role not granted, no
network path to Exchange/Teams endpoints) is caught at the top level, recorded as a single
`{ signal: 'connection', message }` entry, and the script still exits `0` with that
partial result — Node-side, `collectExoComplianceSignals` / `collectTeamsSignals` also
never throw, wrapping any bridge-level failure (spawn error, timeout, JSON parse failure)
into the same `{ collectedAt, errors: [{ signal: 'connection', message }] }` shape. This
mirrors `collectAndScoreTenant`'s (`src/worker/collectTenant.ts`) principle that one
tenant/one signal source failing must never block collection for anyone else.

## Environmental dependencies worth flagging

- **DNS resolution for DMARC**: there is no Exchange Online cmdlet for DMARC (it is a DNS
  TXT record, not tenant configuration). `Collect-ExoComplianceSignals.ps1` resolves
  `_dmarc.<domain>` via `Resolve-DnsName` for each accepted domain. This requires outbound
  DNS resolution to be available from wherever the worker process actually runs — which
  may differ from the path a browser-based check would use. If DNS is unavailable or
  blocked, individual domains simply come back with `record: null, policy: null` rather
  than failing the whole `dmarcConfigs` signal.
- **`pwsh` must be installed and on `PATH`** wherever the Node worker executes
  `runPowerShellCollector`. This environment has PowerShell 7.6.3 installed; production
  deployment targets must too.
- **`ExchangeOnlineManagement` and `MicrosoftTeams` PowerShell Gallery modules must be
  installed** in whatever environment actually runs these scripts in production. They
  could not be installed in the authoring sandbox (see "Verification status").

## Verification status — what was and wasn't validated

What **was** done:
- Every `.ps1` script was parsed with PowerShell's built-in AST parser
  (`[System.Management.Automation.Language.Parser]::ParseFile`) and confirmed to have
  **zero syntax errors** — this catches unbalanced braces, bad tokens, and other
  structural mistakes, but does **not** confirm that any given cmdlet or parameter
  actually exists, is spelled correctly, or behaves as commented.
- Cmdlet names and parameter sets (`Connect-ExchangeOnline -Certificate -AppId
  -Organization`, `Connect-IPPSSession`, `Connect-MicrosoftTeams -Certificate
  -ApplicationId -TenantId`, `X509Certificate2.CreateFromPemFile` /
  `CreateFromEncryptedPemFile`, `Get-AdminAuditLogConfig`'s Security & Compliance vs.
  Exchange Online session behavior) were checked against Microsoft Learn documentation
  during authoring, and are believed correct as of that research.
- `authConfig.certificatePem`'s combined-cert+key convention was confirmed against the
  actual `@azure/identity` `ClientCertificateCredential` type definitions installed in
  this repo's `node_modules` (not just external docs) — this is the same value already
  flowing through `src/lib/graph/authClient.ts` today.
- TypeScript: `npm run typecheck` and `npm run lint` were run and pass for everything
  added in this module (see the PR/commit this file ships with for confirmation at time
  of writing).

What was **NOT** done, and must happen before production use:
- **No live connection to a real Exchange Online, Security & Compliance, or Microsoft
  Teams tenant.** The `ExchangeOnlineManagement` and `MicrosoftTeams` PowerShell Gallery
  modules could not be installed in this sandbox (PSGallery registration failed —
  appears specific to the Gallery's OData protocol; NuGet/npm registries worked
  normally), so no cmdlet's exact runtime behavior, exact output property names/casing,
  or exact error message shape could be confirmed empirically.
- Several field derivations are explicitly marked in code comments as **best-effort
  heuristics pending live-tenant validation**, specifically:
  - `sharingPolicies[].sharesCalendarDetailsExternally` (parsing `SharingPolicy.Domains`
    entries).
  - `hostedContentFilterPolicies[].isEffectivelyDisabled` (inferring "no meaningful
    action" from spam-action enum values).
  - `teamsFederationConfig.allowedDomainsIsUnrestricted` (inferring "no allow-list" from
    `Get-CsTenantFederationConfiguration`'s `AllowedDomains`-shaped output).
- Whether `Connect-ExchangeOnline -Organization` accepts a raw Entra tenant GUID (which is
  what this bridge has on hand) versus strictly requiring the tenant's primary
  `*.onmicrosoft.com` domain is **unconfirmed**. The script currently passes
  `$EntraTenantId` (the GUID) as the best available value. If a real tenant connection
  fails specifically on the `-Organization` parameter, wiring the tenant's verified
  `.onmicrosoft.com` domain through (if/when that's stored in the onboarding record)
  is the documented next step.
- The PFX re-export round-trip performed on the in-memory certificate before connecting
  (to work around a reported "ephemeral key" export/persistence quirk on some platforms
  for certificates built via `CreateFromPemFile`) is included defensively but its
  necessity on Linux/PowerShell 7 specifically is **unverified**.

**Do not treat this subsystem as production-ready until at least one full run against a
real (ideally a dedicated test/sandbox) Microsoft 365 tenant has been completed and the
above unknowns have been resolved.**
