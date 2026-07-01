/**
 * Reusable retry/backoff middleware for the Microsoft Graph SDK's `Middleware` chain.
 *
 * Graph throttles aggressively per-tenant and per-app, and can also return transient failures
 * during upstream incidents. This middleware:
 *  - Retries on 429 (Too Many Requests), 503 (Service Unavailable), and 504 (Gateway Timeout).
 *  - Honors the `Retry-After` header (seconds, or an HTTP-date) when Graph provides one.
 *  - Falls back to exponential backoff with full jitter when no `Retry-After` is present.
 *  - Caps both the number of attempts and the total wall-clock time spent retrying, so a
 *    persistently throttled/unhealthy tenant can never hang a collection cycle indefinitely.
 *
 * This is written as a single reusable `Middleware` class (rather than being copy-pasted per
 * collector) and is composed into the full middleware chain in `authClient.ts`.
 */

import { HTTPMessageHandler, type Context, type Middleware } from '@microsoft/microsoft-graph-client';

const RETRYABLE_STATUS_CODES = new Set([429, 503, 504]);

/** Hard ceiling on attempts regardless of caller-supplied config, to bound worst-case behavior. */
const ABSOLUTE_MAX_RETRIES = 5;

/** Hard ceiling on total time spent retrying a single request, regardless of caller config. */
const ABSOLUTE_MAX_TOTAL_WAIT_MS = 60_000;

const DEFAULT_BASE_DELAY_MS = 500;
const DEFAULT_MAX_DELAY_MS = 30_000;

export interface RetryMiddlewareOptions {
  /** Max retry attempts after the initial try. Capped at ABSOLUTE_MAX_RETRIES. Default 5. */
  maxRetries?: number;
  /** Max total wall-clock time (ms) to spend retrying a single request. Capped at ABSOLUTE_MAX_TOTAL_WAIT_MS. Default 60s. */
  maxTotalWaitMs?: number;
  /** Base delay (ms) for exponential backoff when no Retry-After header is present. Default 500ms. */
  baseDelayMs?: number;
  /** Max backoff delay (ms) before jitter, for any single retry attempt. Default 30s. */
  maxDelayMs?: number;
  /** Injectable sleep function, for unit testing without real timers. */
  sleep?: (ms: number) => Promise<void>;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Parses a Retry-After header value (either delta-seconds or an HTTP-date) into milliseconds. */
function parseRetryAfterMs(headerValue: string | null): number | undefined {
  if (!headerValue) return undefined;

  const asSeconds = Number(headerValue);
  if (Number.isFinite(asSeconds) && asSeconds >= 0) {
    return asSeconds * 1000;
  }

  const asDate = Date.parse(headerValue);
  if (!Number.isNaN(asDate)) {
    return Math.max(0, asDate - Date.now());
  }

  return undefined;
}

/** Exponential backoff with full jitter: a uniformly random delay in [0, min(maxDelay, base * 2^attempt)]. */
function computeBackoffMs(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
  const cap = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
  return Math.random() * cap;
}

/**
 * Middleware implementing exponential-backoff-with-jitter retry, Retry-After aware, for Graph's
 * transient failure/throttling status codes. Implements the SDK's `Middleware` contract directly
 * so it can be spliced into a `Client.initWithMiddleware({ middleware: [...] })` chain.
 */
export class RetryWithBackoffMiddleware implements Middleware {
  private nextMiddleware!: Middleware;

  private readonly maxRetries: number;
  private readonly maxTotalWaitMs: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: RetryMiddlewareOptions = {}) {
    this.maxRetries = Math.min(options.maxRetries ?? ABSOLUTE_MAX_RETRIES, ABSOLUTE_MAX_RETRIES);
    this.maxTotalWaitMs = Math.min(options.maxTotalWaitMs ?? ABSOLUTE_MAX_TOTAL_WAIT_MS, ABSOLUTE_MAX_TOTAL_WAIT_MS);
    this.baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
    this.maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
    this.sleep = options.sleep ?? defaultSleep;
  }

  setNext(next: Middleware): void {
    this.nextMiddleware = next;
  }

  async execute(context: Context): Promise<void> {
    let totalWaitedMs = 0;

    for (let attempt = 0; ; attempt++) {
      await this.nextMiddleware.execute(context);

      const response = context.response;
      const isRetryableStatus = response !== undefined && RETRYABLE_STATUS_CODES.has(response.status);
      const attemptsExhausted = attempt >= this.maxRetries;

      if (!isRetryableStatus || attemptsExhausted) {
        return;
      }

      const retryAfterMs = parseRetryAfterMs(response.headers?.get('Retry-After') ?? null);
      const delayMs = retryAfterMs ?? computeBackoffMs(attempt, this.baseDelayMs, this.maxDelayMs);

      if (totalWaitedMs + delayMs > this.maxTotalWaitMs) {
        // Retrying further would blow the overall time budget for this request; surface the
        // last (throttled/transient-failure) response as-is rather than waiting indefinitely.
        return;
      }

      totalWaitedMs += delayMs;
      await this.sleep(delayMs);
    }
  }
}

export interface RetryChainOptions {
  maxRetries?: number;
  maxTotalWaitMs?: number;
}

/**
 * Builds the retry portion of a middleware chain: a `RetryWithBackoffMiddleware` wired to a
 * terminal `HTTPMessageHandler` (the handler that actually performs the `fetch`). Callers that
 * also need authentication should prepend an `AuthenticationHandler` before this chain — see
 * `createGraphClient` in `authClient.ts`, which is the sole intended caller.
 */
export function createRetryMiddlewareChain(options: RetryChainOptions = {}): Middleware {
  const retryMiddleware = new RetryWithBackoffMiddleware(options);
  const httpMessageHandler = new HTTPMessageHandler();
  retryMiddleware.setNext(httpMessageHandler);
  return retryMiddleware;
}
