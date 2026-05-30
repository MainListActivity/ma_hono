/**
 * Claim hook source: at token issuance, the IdP calls an external hook once per
 * login and maps fields from the returned object onto custom claims. This lets a
 * relying party (e.g. surreal-ck) inject dynamic claims — workspace db/ac scope,
 * can_create_workspace — that the IdP itself has no knowledge of.
 *
 * One login = one hook call. Multiple `hook`-source claims on the same client
 * share a single fetch (deduped by the caller in resolveCustomClaims).
 */

export interface ClaimHookConfig {
  /** Absolute URL of the hook endpoint (GET). */
  url: string;
  /** Optional custom header name used to authenticate the hook request. */
  authHeaderName?: string | null;
  /** Optional custom header value used to authenticate the hook request. */
  authHeaderValue?: string | null;
}

export interface ClaimHookContext {
  subject: string;
  email: string | null;
}

export type ClaimHookFetcher = (
  config: ClaimHookConfig,
  context: ClaimHookContext
) => Promise<Record<string, unknown>>;

/**
 * Default fetcher: GET {url}?subject=..&email=.. with an optional custom auth header.
 * Returns the parsed JSON object, or `{}` on any failure (non-2xx, network, bad JSON)
 * so that a hook outage degrades to "no hook claims" rather than blocking login.
 */
export const fetchClaimHook: ClaimHookFetcher = async (config, context) => {
  let url: URL;
  try {
    url = new URL(config.url);
  } catch {
    return {};
  }

  url.searchParams.set("subject", context.subject);
  if (context.email !== null && context.email !== "") {
    url.searchParams.set("email", context.email);
  }

  const headers = new Headers({ accept: "application/json" });
  if (
    config.authHeaderName !== undefined &&
    config.authHeaderName !== null &&
    config.authHeaderName !== "" &&
    config.authHeaderValue !== undefined &&
    config.authHeaderValue !== null &&
    config.authHeaderValue !== ""
  ) {
    try {
      headers.set(config.authHeaderName, config.authHeaderValue);
    } catch {
      return {};
    }
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: "GET",
      headers
    });
  } catch {
    return {};
  }

  if (!response.ok) {
    return {};
  }

  try {
    const body = (await response.json()) as unknown;
    return body !== null && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
};
