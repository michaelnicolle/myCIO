/**
 * KMS abstraction for wrapping/unwrapping the data-encryption key (DEK) used by
 * src/lib/crypto/envelope.ts. This module intentionally does NOT talk to any real
 * key vault — it defines the interface a future PR should implement against Azure
 * Key Vault (or AWS KMS / GCP KMS, if the platform ever needs multi-cloud support).
 *
 * DO NOT add a real Key Vault SDK call here without also adding key rotation,
 * access-policy, and audit coverage for it — see README.md "Security model".
 */

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
