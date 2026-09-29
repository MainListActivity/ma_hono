import type { Client } from "../clients/types";

/**
 * Resource indicators are deliberately configured by the server.  A client
 * may ask for this resource, but it can never mint an arbitrary audience by
 * putting a different URI in an authorize or token request.
 */
export const DEFAULT_MCP_SCOPES = [
  "content.read",
  "content.submit",
  "content.publish",
  "content.withdraw",
  "content.restore",
  "content.source.manage"
] as const;

export interface ManagedResourcePolicy {
  resource: string;
  scopes: readonly string[];
}

const normalizeScopes = (scope: string): string[] =>
  [...new Set(scope.split(/\s+/u).map((value) => value.trim()).filter(Boolean))];

export const createManagedResourcePolicy = ({
  resource,
  scopes = DEFAULT_MCP_SCOPES
}: {
  resource: string;
  scopes?: readonly string[];
}): ManagedResourcePolicy => {
  const normalizedResource = resource.trim();

  try {
    const url = new URL(normalizedResource);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
      throw new Error("resource must be an https URL without credentials or fragments");
    }
  } catch {
    throw new Error("resource must be an absolute https URL");
  }

  const normalizedScopes = [...new Set(scopes.map((scope) => scope.trim()).filter(Boolean))];
  if (normalizedScopes.length === 0 || normalizedScopes.some((scope) => scope === "openid")) {
    throw new Error("managed resource scopes must be non-empty and must not redefine openid");
  }

  return {
    resource: normalizedResource,
    scopes: normalizedScopes
  };
};

export const validateResourceRequest = ({
  client,
  policy,
  resource,
  scope
}: {
  client: Client;
  policy: ManagedResourcePolicy | null;
  resource: string | null;
  scope: string;
}): { ok: true; resource: string | null; scope: string } | { ok: false; reason: string } => {
  const normalizedScope = normalizeScopes(scope);

  if (resource === null || resource.trim().length === 0) {
    if (client.accessTokenAudience !== null && policy !== null && client.accessTokenAudience === policy.resource) {
      return { ok: false, reason: "resource is required for managed MCP clients" };
    }

    return {
      ok: true,
      resource: null,
      scope: normalizedScope.join(" ")
    };
  }

  if (policy === null || resource.trim() !== policy.resource) {
    return { ok: false, reason: "resource is not managed by this authorization server" };
  }

  if (client.accessTokenAudience !== policy.resource) {
    return { ok: false, reason: "client is not registered for the requested resource" };
  }

  const allowedScopes = new Set(["openid", ...policy.scopes]);
  if (normalizedScope.some((scopeName) => !allowedScopes.has(scopeName))) {
    return { ok: false, reason: "scope is not allowed for the requested resource" };
  }

  if (
    client.allowedScopes !== undefined &&
    normalizedScope.some(
      (scopeName) => scopeName !== "openid" && !client.allowedScopes?.includes(scopeName)
    )
  ) {
    return { ok: false, reason: "scope exceeds the client's registered permission" };
  }

  return {
    ok: true,
    resource: policy.resource,
    scope: normalizedScope.join(" ")
  };
};

export const isManagedMcpClient = (
  client: Client,
  policy: ManagedResourcePolicy | null
) => policy !== null && client.accessTokenAudience === policy.resource;
