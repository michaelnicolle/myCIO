/**
 * Builds an authenticated Microsoft Graph client for a single customer tenant using the
 * OAuth2 client-credentials flow (application permissions only — no delegated/user context).
 *
 * This module intentionally knows NOTHING about:
 *  - how credentials are stored (database, secret manager, etc.)
 *  - how credentials are encrypted/decrypted at rest
 *  - which tenant record they belong to in our own data model
 *
 * The caller is responsible for decrypting credentials and handing us plain values. We only
 * hold them in memory for the lifetime of the credential object used to mint tokens, and we
 * never log secret/certificate material — including in error paths (see `toSafeError` below).
 */

import { ClientCertificateCredential, ClientSecretCredential, type TokenCredential } from '@azure/identity';
import { AuthenticationHandler, Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials';

import { REQUIRED_GRAPH_APPLICATION_SCOPES } from '@/types/domain';
import { createRetryMiddlewareChain } from './rateLimiter';

/** Graph's default resource scope for client-credentials (app-only) tokens. */
const GRAPH_DEFAULT_SCOPE = 'https://graph.microsoft.com/.default';

/**
 * Certificate-based credential material. This is the PRIMARY, preferred auth path — certs are
 * harder to exfiltrate at rest, support proof-of-possession, and are easier to rotate without a
 * shared-secret round trip. The certificate thumbprint is derived by the underlying MSAL client
 * from the certificate itself; it is not a separate input.
 */
export interface GraphCertificateAuthConfig {
  kind: 'certificate';
  entraTenantId: string;
  clientId: string;
  /** PEM-encoded certificate + private key, already decrypted by the caller. */
  certificatePem: string;
  /** Optional password if the PEM private key is encrypted. */
  certificatePassword?: string;
}

/**
 * Client-secret credential material.
 *
 * FALLBACK PATH ONLY. Client secrets are weaker than certificates (bearer-token-like, easier to
 * leak via logs/config, no proof-of-possession) and Microsoft is steering app registrations away
 * from long-lived secrets. New tenant onboardings should prefer GraphCertificateAuthConfig;
 * existing secret-based tenants should be migrated to certificates and this path phased out
 * per-tenant as that migration completes.
 */
export interface GraphSecretAuthConfig {
  kind: 'secret';
  entraTenantId: string;
  clientId: string;
  /** Already-decrypted plaintext client secret. */
  clientSecret: string;
}

export type GraphAuthConfig = GraphCertificateAuthConfig | GraphSecretAuthConfig;

/**
 * Redacts any credential material from a config-shaped value before it is ever logged. We never
 * log secrets/keys directly, but this guards against accidentally stringifying a config object
 * (e.g. `console.error(config)`) in some future edit to this module or a caller.
 */
export function redactAuthConfig(config: Record<string, unknown>): Record<string, unknown> {
  const SENSITIVE_KEYS = ['certificatePem', 'certificatePassword', 'clientSecret'] as const;
  const redacted: Record<string, unknown> = { ...config };
  for (const key of SENSITIVE_KEYS) {
    if (key in redacted) {
      redacted[key] = '[REDACTED]';
    }
  }
  return redacted;
}

/**
 * Wraps an unknown error in a new Error containing only our own static context plus the
 * upstream SDK's message. We never interpolate raw config/credential fields here, so even if an
 * SDK error's `message` were to embed request details, we are not adding any secret material of
 * our own to the output.
 */
function toSafeError(err: unknown, context: string): Error {
  const message = err instanceof Error ? err.message : String(err);
  const safe = new Error(`[graph:auth] ${context}: ${message}`);
  safe.name = 'GraphAuthError';
  return safe;
}

function buildCredential(config: GraphAuthConfig): TokenCredential {
  try {
    if (config.kind === 'certificate') {
      return new ClientCertificateCredential(config.entraTenantId, config.clientId, {
        certificate: config.certificatePem,
        certificatePassword: config.certificatePassword,
      });
    }

    // Fallback path — see GraphSecretAuthConfig doc comment.
    return new ClientSecretCredential(config.entraTenantId, config.clientId, config.clientSecret);
  } catch (err) {
    throw toSafeError(err, 'failed to construct credential');
  }
}

export interface GraphClientOptions {
  /** Override the default max retry attempts for the rate-limit/retry middleware. */
  maxRetries?: number;
  /** Override the default overall retry time budget (ms) for the rate-limit/retry middleware. */
  maxTotalWaitMs?: number;
}

/**
 * Builds a `Client` (from `@microsoft/microsoft-graph-client`) authenticated against a single
 * customer Entra tenant via app-only client-credentials, wired with retry/backoff middleware for
 * 429/503/504 handling.
 *
 * Every token minted through this client is scoped to `.default`, meaning the actual permissions
 * granted are whatever admin consent has been granted to the app registration in the customer
 * tenant — which should always be exactly `REQUIRED_GRAPH_APPLICATION_SCOPES` (see
 * src/lib/graph/README.md). This function does not itself request individual scopes; Graph
 * app-only tokens are all-or-nothing per `.default`.
 *
 * NOTE on middleware wiring: `Client.initWithMiddleware` throws if both `authProvider` and
 * `middleware` are supplied together (they're mutually exclusive init paths in this SDK version).
 * Since we need custom retry/backoff behavior, we build the *entire* chain ourselves —
 * `AuthenticationHandler` (wrapping our token credential) feeding into the retry middleware,
 * which in turn terminates in `HTTPMessageHandler` (see `createRetryMiddlewareChain`) — and pass
 * only `middleware`, never `authProvider`, to `initWithMiddleware`.
 */
export function createGraphClient(config: GraphAuthConfig, options: GraphClientOptions = {}): Client {
  const credential: TokenCredential = buildCredential(config);

  const authProvider = new TokenCredentialAuthenticationProvider(credential, {
    scopes: [GRAPH_DEFAULT_SCOPE],
  });
  const authenticationHandler = new AuthenticationHandler(authProvider);

  const retryChain = createRetryMiddlewareChain({
    maxRetries: options.maxRetries,
    maxTotalWaitMs: options.maxTotalWaitMs,
  });
  authenticationHandler.setNext(retryChain);

  return Client.initWithMiddleware({
    middleware: authenticationHandler,
  });
}

/** Re-exported so collectors/orchestrator can reference the canonical scope list without a second import path. */
export const GRAPH_APPLICATION_SCOPES = REQUIRED_GRAPH_APPLICATION_SCOPES;
