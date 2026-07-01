# src/lib/crypto

Envelope encryption for tenant Microsoft Graph credentials (client secrets and certificate
private keys) at rest. See `envelope.ts` and `kms.ts` for the full implementation; this document
covers the security model and the one-time Azure Key Vault setup an operator must complete before
`CREDENTIAL_KMS_KEY_ID` / `AZURE_KEY_VAULT_URL` can be configured in production.

## Files

| File | Responsibility |
| --- | --- |
| `envelope.ts` | `encryptCredential` / `decryptCredential` — AES-256-GCM envelope encryption with a fresh per-credential data key (DEK). Resolves which `KmsProvider` to use via `getKmsProvider()` and enforces the production-vs-dev-key rules below. |
| `kms.ts` | `KmsProvider` interface, `WrappedKey` type, `NotConfiguredKmsProvider` (always-throws stub), and `AzureKeyVaultKmsProvider` (real production backend). |

## Security model

1. Every credential value is encrypted with a fresh, random 256-bit data encryption key (DEK)
   using AES-256-GCM (authenticated encryption). The DEK is used exactly once, for exactly one
   credential value, and is zeroed (`Buffer.fill(0)`) as soon as it's no longer needed.
2. The DEK itself is never persisted in plaintext. It is "wrapped" (encrypted) by a `KmsProvider`
   before being stored alongside the ciphertext:
   - **Production**: `CREDENTIAL_KMS_KEY_ID` and `AZURE_KEY_VAULT_URL` must both be set, and
     `getKmsProvider()` constructs an `AzureKeyVaultKmsProvider`. If only one (or neither) is set
     in production, credential encryption refuses to start — there is no silent fallback.
   - **Local development ONLY**: `CREDENTIAL_DEV_DATA_KEY` (32-byte base64) may be set instead,
     deriving a static local "wrapping" key. This path is loudly logged once at first use and is
     hard-refused whenever `NODE_ENV === 'production'`, even if the env var happens to be set
     (e.g. leftover from a bad deploy).
3. Key Vault (or the dev-key path) only ever sees the small 32-byte DEK, never the credential
   plaintext. This bounds Key Vault call volume to O(1) per credential encrypt/decrypt operation,
   regardless of the credential's size (a certificate private key PEM vs. a short client secret
   cost the same number of Key Vault calls).
4. Nothing in this module writes plaintext secrets, DEKs, or wrapped keys to logs or thrown error
   messages. Every error path re-throws a sanitized message (see `sanitizeErrorMessage` in
   `envelope.ts` and the equivalent handling in `AzureKeyVaultKmsProvider`).

## Azure Key Vault setup (required before configuring `CREDENTIAL_KMS_KEY_ID` in production)

`AzureKeyVaultKmsProvider` (`kms.ts`) uses Key Vault's `CryptographyClient` to wrap/unwrap the DEK
with the **RSA-OAEP-256** key-wrap algorithm (RSA-OAEP with SHA-256 — the strongest, current,
non-deprecated asymmetric wrap algorithm Key Vault documents; plain `RSA-OAEP` uses SHA-1 and
`RSA1_5`/PKCS#1 v1.5 is legacy). This requires an **RSA key** in Key Vault — an EC key or Managed
HSM key with no wrap/unwrap key operations will not work.

An operator must do the following once, before setting `CREDENTIAL_KMS_KEY_ID` /
`AZURE_KEY_VAULT_URL` in a production environment:

1. **Create (or identify) a Key Vault instance.**

   ```sh
   az keyvault create \
     --name <vault-name> \
     --resource-group <resource-group> \
     --location <region>
   ```

   Use Key Vault's default **Standard** (or **Premium**, if HSM-backed keys are required) SKU —
   Managed HSM is not required for this use case, though it is also supported if your compliance
   posture demands it.

2. **Create an RSA key** with at least 2048 bits (3072 or 4096 recommended for long-lived
   production keys) and the `wrapKey`/`unwrapKey` key operations enabled:

   ```sh
   az keyvault key create \
     --vault-name <vault-name> \
     --name posture-platform-credential-wrap \
     --kty RSA \
     --size 3072 \
     --ops wrapKey unwrapKey
   ```

   The `--name` value here is what goes into `CREDENTIAL_KMS_KEY_ID` (see "Env var semantics"
   below) — it is a key **name**, not a full resource ID/URL.

3. **Grant the application's identity `wrapKey` + `unwrapKey` permissions on that key only** — not
   broader Key Vault management permissions, and not access to other keys/secrets/certificates in
   the vault. Prefer Key Vault's RBAC authorization model with the built-in
   **Key Vault Crypto User** role (`wrapKey`/`unwrapKey`/`get` on keys, no create/delete/list-all),
   scoped to the specific key if using a data-plane role assignment, e.g.:

   ```sh
   az role assignment create \
     --role "Key Vault Crypto User" \
     --assignee <app-client-id-or-managed-identity-principal-id> \
     --scope "$(az keyvault show --name <vault-name> --query id -o tsv)"
   ```

   If the vault instead uses the legacy vault access-policy model, grant only the `wrapKey` and
   `unwrapKey` key permissions (no `get`/`list`/`create`/`delete`/`import` unless a separate
   operational need requires it) to the application's identity.

4. **Enable soft-delete and purge protection** on the vault (the default for new vaults as of
   recent API versions, but verify) so an accidental key deletion doesn't make every encrypted
   credential permanently unrecoverable:

   ```sh
   az keyvault update \
     --name <vault-name> \
     --enable-purge-protection true
   ```

5. **Enable diagnostic logging** (`AuditEvent` category) on the vault, sent to your central log
   sink, so every wrap/unwrap operation against the credential key is independently auditable
   outside of this application.

6. **Never delete or disable the key version(s) referenced by `kmsKeyVersion` on any existing
   encrypted credential row.** Key rotation is supported (create a new key version; new
   encryptions automatically pick up the new current version; `WrappedKey.kmsKeyVersion` records
   whichever version Key Vault actually used per operation), but old versions must remain enabled
   as long as any stored `EncryptedBlob` references them, or those credentials become permanently
   undecryptable. A full re-encryption/rotation job (re-wrapping every DEK under a new key
   version and updating stored `kmsKeyVersion`) is the safe way to fully retire an old key version.

## Env var semantics

| Env var | Meaning |
| --- | --- |
| `AZURE_KEY_VAULT_URL` | Base URL of the Key Vault instance, e.g. `https://<vault-name>.vault.azure.net/`. Required together with `CREDENTIAL_KMS_KEY_ID` (both or neither) once `AzureKeyVaultKmsProvider` is in use. |
| `CREDENTIAL_KMS_KEY_ID` | **Pre-existing env var; semantic finalized here.** The **name** of the RSA key within that vault (e.g. `posture-platform-credential-wrap`) — not a full Key Vault resource ID/ARN. Kept under this name rather than renamed because other code/docs already reference `CREDENTIAL_KMS_KEY_ID`. |
| `CREDENTIAL_KMS_KEY_VERSION` | Optional. Pins a specific Key Vault key version instead of always resolving to the key's current/latest version. Usually left unset; the actual version Key Vault used for each wrap operation is always recorded in `WrappedKey.kmsKeyVersion` regardless of whether this is set, so rotating the key's current version does not affect the ability to decrypt older records. |
| `CREDENTIAL_DEV_DATA_KEY` | Local-development-only fallback (32-byte base64 AES key). Hard-refused when `NODE_ENV === 'production'`. |

## Authentication to Key Vault

`AzureKeyVaultKmsProvider` authenticates using `DefaultAzureCredential` from `@azure/identity`
(already a dependency for the Graph client-credential flow in `src/lib/graph`). This class does
not hardcode a specific credential-acquisition mechanism — `DefaultAzureCredential` transparently
tries, in order, roughly:

1. Environment variables `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` (a service
   principal) — the mechanism used when running off Azure infrastructure (e.g. on Railway).
2. Workload Identity / Managed Identity — used automatically when actually running on Azure
   infrastructure (App Service, AKS, VMs, etc.) with an identity assigned, no env vars required.
3. Developer-login fallbacks (Azure CLI, Azure PowerShell, VS Code), useful only for local
   interactive testing against a real vault — not relevant to CI/production.

Whichever mechanism resolves, the identity it produces must have been granted `wrapKey` +
`unwrapKey` on the configured key as described above; `DefaultAzureCredential` only handles
*authentication*, not *authorization*.

**Do not** set `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` to the same values as
`AZURE_AD_CLIENT_ID` / `AZURE_AD_CLIENT_SECRET` / `AZURE_AD_TENANT_ID` (the portal-login app
registration) — these should be a separate app registration/service principal scoped only to Key
Vault crypto access, following least privilege.

## Do not add a real KMS call without also covering rotation, access-policy, and audit

If a second KMS backend is ever added (AWS KMS, GCP KMS, a different Key Vault client, etc.),
apply the same bar as `AzureKeyVaultKmsProvider`: least-privilege key permissions, documented key
rotation story, audit logging, and sanitized error handling that never risks leaking key material
or credential plaintext in a thrown error.
