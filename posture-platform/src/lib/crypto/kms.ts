/**
 * KMS abstraction for wrapping/unwrapping the data-encryption key (DEK) used by
 * src/lib/crypto/envelope.ts. This module defines the interface every backend must
 * implement (see `KmsProvider`) plus the current implementations:
 *   - `NotConfiguredKmsProvider`: a deliberate always-throws stub for the
 *     "nothing is configured" case.
 *   - `AzureKeyVaultKmsProvider`: the real production backend, wrapping/unwrapping
 *     the DEK via Azure Key Vault's `CryptographyClient`. See README.md
 *     ("Azure Key Vault setup") for the one-time operator setup this requires
 *     (key type, permissions, access policy) before it will work.
 *
 * DO NOT add a real Key Vault SDK call here without also adding key rotation,
 * access-policy, and audit coverage for it — see README.md "Security model".
 */

import { DefaultAzureCredential } from '@azure/identity';
import { CryptographyClient, type KeyWrapAlgorithm } from '@azure/keyvault-keys';

/** A KMS-wrapped (encrypted) data key, opaque to callers. */
export interface WrappedKey {
  /** Base64-encoded ciphertext of the wrapped data key. */
  wrappedKeyB64: string;
  /** Identifier of the KMS key used to wrap, e.g. Key Vault key name or ARN. */
  kmsKeyId: string;
  /** Version of the KMS key used to wrap, so rotation doesn't break old records. */
  kmsKeyVersion: string;
}

/**
 * Interface every KMS backend must implement. Implementations must never log or
 * throw errors containing the plaintext data key.
 */
export interface KmsProvider {
  /** Human-readable provider tag persisted alongside encrypted blobs (e.g. "azure-keyvault", "dev-local"). */
  readonly providerTag: string;

  /** Encrypts (wraps) a raw data key with the configured master key. */
  wrapKey(plaintextDataKey: Buffer): Promise<WrappedKey>;

  /** Decrypts (unwraps) a previously-wrapped data key back to its raw bytes. */
  unwrapKey(wrapped: WrappedKey): Promise<Buffer>;
}

/**
 * Placeholder provider used whenever CREDENTIAL_KMS_KEY_ID is not configured and we
 * are NOT falling back to the local-dev path (e.g. production with nothing configured
 * at all). Always throws — this is deliberate. There must be no silent no-op KMS.
 */
export class NotConfiguredKmsProvider implements KmsProvider {
  readonly providerTag = 'not-configured';

  private fail(): never {
    throw new Error(
      'Credential KMS provider is not configured. Set CREDENTIAL_KMS_KEY_ID to a valid ' +
        'Key Vault (or equivalent) key identifier and implement a real KmsProvider ' +
        '(see src/lib/crypto/kms.ts) before handling tenant credentials in this environment. ' +
        'Local development may instead set CREDENTIAL_DEV_DATA_KEY, which is refused in production.',
    );
  }

  wrapKey(): Promise<WrappedKey> {
    this.fail();
  }

  unwrapKey(): Promise<Buffer> {
    this.fail();
  }
}

/**
 * Wrap algorithm used for all Key Vault wrap/unwrap operations performed by this
 * provider. RSA-OAEP-256 (RSA-OAEP with SHA-256, per RFC 7518 / JWA "RSA-OAEP-256")
 * is the strongest, current, non-deprecated asymmetric wrap algorithm Key Vault's
 * `CryptographyClient` documents — plain "RSA-OAEP" uses SHA-1 and "RSA1_5"
 * (PKCS#1 v1.5) is legacy/deprecated. This requires the underlying Key Vault key to
 * be an RSA key (see README.md for the exact `az keyvault key create` invocation).
 */
const WRAP_ALGORITHM: KeyWrapAlgorithm = 'RSA-OAEP-256';

/**
 * Real production KmsProvider backed by Azure Key Vault. Only the 32-byte AES DEK
 * generated per-credential in envelope.ts is ever sent to Key Vault — the
 * credential plaintext itself never leaves this process. Every wrap/unwrap call is
 * therefore O(1) with respect to credential size and Key Vault call volume scales
 * with the number of credential operations, not their payload size.
 *
 * Authentication is via `DefaultAzureCredential` (@azure/identity), which
 * transparently tries, in order: environment variables (`AZURE_CLIENT_ID` /
 * `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`, i.e. a service principal — the
 * mechanism used when running off-Azure, e.g. on Railway), Workload Identity,
 * Managed Identity (when actually running on Azure infrastructure), and the
 * Azure CLI/PowerShell/VS Code developer logins as further fallbacks. This class
 * never chooses a specific mechanism itself, by design (requirement: transparent
 * managed-identity support without hardcoding how credentials are acquired).
 */
export class AzureKeyVaultKmsProvider implements KmsProvider {
  readonly providerTag = 'azure-keyvault';

  private readonly vaultUrl: string;
  private readonly keyName: string;
  private readonly keyVersion: string | undefined;
  private readonly cryptographyClient: CryptographyClient;

  /**
   * @param vaultUrl - Key Vault URL, e.g. `https://<vault-name>.vault.azure.net/`
   *   (from `AZURE_KEY_VAULT_URL`).
   * @param keyName - Name of the RSA key in that vault used to wrap/unwrap DEKs
   *   (from `CREDENTIAL_KMS_KEY_ID` — see README.md for why that existing env var's
   *   semantic is "Key Vault key name", not a full resource ID).
   * @param keyVersion - Optional specific key version to pin
   *   (from `CREDENTIAL_KMS_KEY_VERSION`). When omitted, Key Vault resolves the
   *   key's current/latest version at call time; the *actual* version used is
   *   always read back from the operation result, never assumed, so
   *   `WrappedKey.kmsKeyVersion` is always accurate even when this is unset.
   */
  constructor(vaultUrl: string, keyName: string, keyVersion?: string) {
    this.vaultUrl = vaultUrl;
    this.keyName = keyName;
    this.keyVersion = keyVersion;

    // Passing an unversioned (or versioned) key identifier URL, rather than a
    // pre-fetched KeyVaultKey, lets the CryptographyClient resolve the current
    // version lazily and lets Key Vault (not this code) be the source of truth
    // for "which version is current".
    const keyIdentifier = keyVersion
      ? `${this.vaultUrl}keys/${this.keyName}/${keyVersion}`
      : `${this.vaultUrl}keys/${this.keyName}`;

    const credential = new DefaultAzureCredential();
    this.cryptographyClient = new CryptographyClient(keyIdentifier, credential);
  }

  async wrapKey(plaintextDataKey: Buffer): Promise<WrappedKey> {
    try {
      const result = await this.cryptographyClient.wrapKey(WRAP_ALGORITHM, plaintextDataKey);
      return {
        wrappedKeyB64: Buffer.from(result.result).toString('base64'),
        kmsKeyId: this.keyName,
        kmsKeyVersion: this.extractKeyVersion(result.keyID),
      };
    } catch (err) {
      throw this.sanitizedError('wrap', err);
    }
  }

  async unwrapKey(wrapped: WrappedKey): Promise<Buffer> {
    try {
      const encryptedKey = Buffer.from(wrapped.wrappedKeyB64, 'base64');
      const result = await this.cryptographyClient.unwrapKey(WRAP_ALGORITHM, encryptedKey);
      return Buffer.from(result.result);
    } catch (err) {
      throw this.sanitizedError('unwrap', err);
    }
  }

  /**
   * Key Vault key identifiers are of the form
   * `https://{vault}.vault.azure.net/keys/{name}/{version}`. The wrap/unwrap
   * result's `keyID` reflects whichever version Key Vault actually used to
   * service the request (relevant when this provider was constructed without a
   * pinned `keyVersion`, e.g. after a key rotation). We must record that real
   * version in `WrappedKey.kmsKeyVersion`, never the version this instance was
   * configured with, so rotation doesn't silently mislabel older records.
   */
  private extractKeyVersion(keyId: string | undefined): string {
    if (!keyId) {
      // Should not happen for a successful Key Vault operation, but fail loudly
      // rather than fabricate a version string that could break future unwraps.
      throw new Error(
        'Azure Key Vault did not return a key identifier for this operation; cannot determine ' +
          'the key version that was used.',
      );
    }
    const segments = keyId.split('/').filter(Boolean);
    const version = segments[segments.length - 1];
    if (!version) {
      throw new Error(`Could not parse a key version from Key Vault key identifier: ${keyId}`);
    }
    return version;
  }

  /**
   * Sanitizes Azure SDK errors before they propagate. The DEK/plaintext are never
   * part of an Azure Key Vault error (Key Vault only ever sees ciphertext-sized
   * blobs and its own diagnostic strings), but we don't trust downstream SDK/HTTP
   * error messages by default — consistent with envelope.ts's `sanitizeErrorMessage`.
   */
  private sanitizedError(operation: 'wrap' | 'unwrap', err: unknown): Error {
    const rawMessage = err instanceof Error ? err.message : 'unknown error';
    const truncated = rawMessage.length > 200 ? `${rawMessage.slice(0, 200)}...(truncated)` : rawMessage;
    return new Error(
      `Azure Key Vault ${operation}Key operation failed for key "${this.keyName}"` +
        `${this.keyVersion ? ` (version ${this.keyVersion})` : ''}: ${truncated}`,
    );
  }
}
