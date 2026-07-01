/**
 * Envelope encryption for tenant Microsoft Graph credentials (client secrets and
 * certificate private keys) at rest.
 *
 * Design (see README.md "Security model", item 3):
 *   - Every credential value is encrypted with a fresh, random 256-bit data
 *     encryption key (DEK) using AES-256-GCM (authenticated encryption).
 *   - The DEK itself is never persisted in plaintext. It is "wrapped" (encrypted)
 *     by a KmsProvider:
 *       (a) In production, CREDENTIAL_KMS_KEY_ID must be set, and a real
 *           KmsProvider (Azure Key Vault, etc.) must be wired up in
 *           src/lib/crypto/kms.ts. Until that real integration lands, the
 *           NotConfiguredKmsProvider throws — there is no silent fallback.
 *       (b) In local development ONLY, CREDENTIAL_DEV_DATA_KEY (32-byte base64)
 *           may be set instead, deriving a static local "wrapping" key. This
 *           path is loudly logged once and is hard-refused whenever
 *           NODE_ENV === 'production'.
 *
 * Callers should only ever use encryptCredential / decryptCredential. Nothing in
 * this module writes plaintext secrets, DEKs, or wrapped keys to logs or thrown
 * error messages.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { KmsProvider, NotConfiguredKmsProvider, WrappedKey } from './kms';

const ALGORITHM = 'aes-256-gcm';
const DEK_LENGTH_BYTES = 32; // AES-256
const IV_LENGTH_BYTES = 12; // 96-bit GCM nonce, NIST-recommended
const DEV_KEY_PROVIDER_TAG = 'dev-local-static-key';

/**
 * Encrypted-at-rest representation of one credential value. Every field here is
 * safe to persist as-is (nothing here is plaintext). `provider`/`kmsKeyId`/
 * `kmsKeyVersion` allow future re-encryption/rotation without breaking the
 * ability to decrypt older rows encrypted under a prior key or provider.
 */
export interface EncryptedBlob {
  /** AES-256-GCM ciphertext of the credential, base64-encoded. */
  ciphertext: string;
  /** GCM initialization vector (nonce), base64-encoded. */
  iv: string;
  /** GCM authentication tag, base64-encoded. */
  authTag: string;
  /** Algorithm used for the data-encryption step; recorded for forward compatibility. */
  algorithm: 'AES-256-GCM';
  /** KMS/dev-key provider tag that wrapped the DEK for this blob (see KmsProvider.providerTag). */
  provider: string;
  /** KMS key id used to wrap the DEK (or a fixed sentinel for the dev-key path). */
  kmsKeyId: string;
  /** KMS key version used to wrap the DEK (or a fixed sentinel for the dev-key path). */
  kmsKeyVersion: string;
  /** The wrapped (encrypted) data key itself, base64-encoded, as returned by the KmsProvider. */
  wrappedDataKey: string;
}

let cachedProvider: KmsProvider | undefined;
let hasLoggedDevKeyWarning = false;

/**
 * Local-dev-only KmsProvider: "wraps" the DEK by encrypting it with a static key
 * derived from CREDENTIAL_DEV_DATA_KEY. This is NOT a substitute for a real KMS —
 * the wrapping key lives in an env var on the same box as the app, so it provides
 * no separation of duties and no HSM-backed protection. It exists purely so local
 * development and tests don't require a live Key Vault.
 */
class DevLocalKmsProvider implements KmsProvider {
  readonly providerTag = DEV_KEY_PROVIDER_TAG;

  private readonly wrappingKey: Buffer;

  constructor(rawKeyB64: string) {
    let decoded: Buffer;
    try {
      decoded = Buffer.from(rawKeyB64, 'base64');
    } catch {
      throw new Error(
        'CREDENTIAL_DEV_DATA_KEY is not valid base64. Generate one with: ' +
          "node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"",
      );
    }
    if (decoded.length !== DEK_LENGTH_BYTES) {
      throw new Error(
        `CREDENTIAL_DEV_DATA_KEY must decode to exactly ${DEK_LENGTH_BYTES} bytes ` +
          `(got ${decoded.length}). Generate one with: ` +
          "node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"",
      );
    }
    this.wrappingKey = decoded;
  }

  async wrapKey(plaintextDataKey: Buffer): Promise<WrappedKey> {
    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.wrappingKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextDataKey), cipher.final()]);
    const authTag = cipher.getAuthTag();
    // Pack iv + authTag + ciphertext together since WrappedKey only carries one opaque string.
    const packed = Buffer.concat([iv, authTag, ciphertext]);
    return {
      wrappedKeyB64: packed.toString('base64'),
      kmsKeyId: 'local-dev-static-key',
      kmsKeyVersion: 'v1',
    };
  }

  async unwrapKey(wrapped: WrappedKey): Promise<Buffer> {
    const packed = Buffer.from(wrapped.wrappedKeyB64, 'base64');
    const iv = packed.subarray(0, IV_LENGTH_BYTES);
    const authTag = packed.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + 16);
    const ciphertext = packed.subarray(IV_LENGTH_BYTES + 16);
    const decipher = createDecipheriv(ALGORITHM, this.wrappingKey, iv);
    decipher.setAuthTag(authTag);
    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      // Never include ciphertext/key material in the error.
      throw new Error('Failed to unwrap data key: authentication failed or key mismatch.');
    }
  }
}

/**
 * Resolves (and caches) the KmsProvider for this process, enforcing the
 * production-safety rule described at the top of this file. Throws at call time
 * (effectively at first use / module init from the caller's perspective) rather
 * than silently falling back.
 */
function getKmsProvider(): KmsProvider {
  if (cachedProvider) {
    return cachedProvider;
  }

  const kmsKeyId = process.env['CREDENTIAL_KMS_KEY_ID'];
  const devDataKey = process.env['CREDENTIAL_DEV_DATA_KEY'];
  const isProduction = process.env['NODE_ENV'] === 'production';

  if (kmsKeyId) {
    // A real KMS key id is configured. Until a real provider implementation
    // (Azure Key Vault, etc.) is wired up in kms.ts, this correctly throws —
    // it must NOT silently proceed with an unimplemented "real" path.
    cachedProvider = new NotConfiguredKmsProvider();
    return cachedProvider;
  }

  if (isProduction) {
    // Hard refuse: production must never run on the dev data key path, even if
    // CREDENTIAL_DEV_DATA_KEY happens to be set (e.g. leftover from a bad deploy).
    throw new Error(
      'Refusing to start credential encryption in production without CREDENTIAL_KMS_KEY_ID ' +
        'configured. The CREDENTIAL_DEV_DATA_KEY fallback is local-development-only and is ' +
        'intentionally disabled when NODE_ENV === "production". Configure a KMS key and a real ' +
        'KmsProvider implementation (see src/lib/crypto/kms.ts) before deploying.',
    );
  }

  if (!devDataKey) {
    throw new Error(
      'No credential encryption key is configured. Set CREDENTIAL_KMS_KEY_ID (production) or ' +
        'CREDENTIAL_DEV_DATA_KEY (local development only, 32-byte base64) before handling tenant ' +
        'credentials.',
    );
  }

  if (!hasLoggedDevKeyWarning) {
    // Loud, one-time, unmistakable warning. Never include the key value itself.
    // eslint-disable-next-line no-console
    console.warn(
      '\n' +
        '!!! =====================================================================\n' +
        '!!! SECURITY WARNING: using CREDENTIAL_DEV_DATA_KEY for credential\n' +
        '!!! encryption. This is a LOCAL-DEVELOPMENT-ONLY fallback with NO KMS/HSM\n' +
        '!!! protection and NO separation of duties. It is refused at startup when\n' +
        '!!! NODE_ENV=production. Do not use this for any tenant with real Graph\n' +
        '!!! credentials outside a local dev environment.\n' +
        '!!! =====================================================================\n',
    );
    hasLoggedDevKeyWarning = true;
  }

  cachedProvider = new DevLocalKmsProvider(devDataKey);
  return cachedProvider;
}

/**
 * Encrypts a plaintext credential value (client secret or certificate private
 * key PEM) for storage. Generates a fresh DEK per call, encrypts the plaintext
 * with it under AES-256-GCM, then wraps the DEK via the configured KmsProvider.
 *
 * The returned EncryptedBlob is safe to persist; it contains no plaintext.
 */
export async function encryptCredential(plaintext: string): Promise<EncryptedBlob> {
  if (!plaintext) {
    throw new Error('encryptCredential: plaintext must be a non-empty string.');
  }

  const provider = getKmsProvider();
  const dek = randomBytes(DEK_LENGTH_BYTES);

  try {
    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv(ALGORITHM, dek, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const wrapped = await provider.wrapKey(dek);

    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: 'AES-256-GCM',
      provider: provider.providerTag,
      kmsKeyId: wrapped.kmsKeyId,
      kmsKeyVersion: wrapped.kmsKeyVersion,
      wrappedDataKey: wrapped.wrappedKeyB64,
    };
  } catch (err) {
    // Re-throw a sanitized error; never let the original message risk echoing
    // plaintext (it shouldn't, but we don't trust downstream KMS SDK errors either).
    throw new Error(
      `Failed to encrypt credential: ${err instanceof Error ? sanitizeErrorMessage(err.message) : 'unknown error'}`,
    );
  } finally {
    dek.fill(0);
  }
}

/**
 * Decrypts a previously-encrypted credential blob back to its plaintext value.
 * Callers must treat the return value as highly sensitive: never log it, never
 * include it in an API response, never persist it anywhere other than passing
 * it directly to the Graph client-credential call that needs it.
 */
export async function decryptCredential(blob: EncryptedBlob): Promise<string> {
  const provider = getKmsProvider();

  if (blob.provider !== provider.providerTag) {
    throw new Error(
      `Cannot decrypt credential: blob was encrypted under provider "${blob.provider}" but the ` +
        `active provider is "${provider.providerTag}". Implement a rotation/migration path in ` +
        'src/lib/crypto before removing support for the prior provider.',
    );
  }

  let dek: Buffer | undefined;
  try {
    dek = await provider.unwrapKey({
      wrappedKeyB64: blob.wrappedDataKey,
      kmsKeyId: blob.kmsKeyId,
      kmsKeyVersion: blob.kmsKeyVersion,
    });

    const decipher = createDecipheriv(ALGORITHM, dek, Buffer.from(blob.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(blob.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, 'base64')),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  } catch (err) {
    throw new Error(
      `Failed to decrypt credential: ${err instanceof Error ? sanitizeErrorMessage(err.message) : 'unknown error'}`,
    );
  } finally {
    dek?.fill(0);
  }
}

/**
 * Strips anything that looks like it could be key/secret material from an error
 * message before it's allowed to propagate. Defense-in-depth only — the real
 * control is that no code path ever puts plaintext/DEK bytes into an Error.
 */
function sanitizeErrorMessage(message: string): string {
  return message.length > 200 ? `${message.slice(0, 200)}...(truncated)` : message;
}
