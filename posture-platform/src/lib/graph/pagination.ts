/**
 * Shared pagination helper for Microsoft Graph collection endpoints.
 *
 * Graph paginates large collections via an opaque `@odata.nextLink` URL rather than
 * page-number/offset semantics. This helper walks that chain using the same authenticated
 * `Client`, capped at a maximum page count so a single huge tenant (e.g. hundreds of thousands
 * of sign-in events) can never cause an unbounded loop or unbounded memory growth.
 */

import type { Client } from '@microsoft/microsoft-graph-client';

/** Hard ceiling on pages fetched for any single collector call, regardless of caller config. */
const ABSOLUTE_MAX_PAGES = 50;

export interface PagedFetchOptions {
  /** Max number of pages to follow via @odata.nextLink. Capped at ABSOLUTE_MAX_PAGES. */
  maxPages?: number;
}

interface ODataCollectionResponse {
  value?: unknown[];
  '@odata.nextLink'?: string;
}

/**
 * Executes an initial Graph request (already configured with `$filter`/`$top`/`$expand` etc. via
 * the caller) and follows `@odata.nextLink` until exhausted or `maxPages` is reached, returning
 * the concatenated raw `value` arrays from every page. Callers are responsible for validating and
 * mapping each raw item to their strict domain type.
 */
export async function fetchAllPages(
  client: Client,
  initialRequest: { get: () => Promise<unknown> },
  options: PagedFetchOptions = {},
): Promise<unknown[]> {
  const maxPages = Math.min(options.maxPages ?? ABSOLUTE_MAX_PAGES, ABSOLUTE_MAX_PAGES);

  const results: unknown[] = [];
  let nextLink: string | undefined;
  let page = 0;

  let response = (await initialRequest.get()) as ODataCollectionResponse;

  while (true) {
    page += 1;
    if (Array.isArray(response.value)) {
      results.push(...response.value);
    }
    nextLink = response['@odata.nextLink'];

    if (!nextLink || page >= maxPages) {
      break;
    }

    // `@odata.nextLink` is a fully-qualified URL already containing the correct query params;
    // `.api()` accepts an absolute URL directly, preserving auth/retry middleware on the client.
    response = (await client.api(nextLink).get()) as ODataCollectionResponse;
  }

  return results;
}
