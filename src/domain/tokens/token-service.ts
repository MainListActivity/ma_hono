import { importJWK, jwtVerify, SignJWT } from "jose";

import type { AuthorizationCodeRepository } from "../authorization/repository";
import { verifyPkce } from "../authorization/pkce";
import type { AccessTokenClaimsRepository } from "../clients/access-token-claims-repository";
import {
  resolveCustomClaims,
  type ResolveCustomClaimsHookDeps
} from "../clients/resolve-custom-claims";
import type { ClaimHookFetcher } from "../clients/claim-hook-client";
import type {
  ClientAuthMethodPolicyRepository,
  ClientRepository
} from "../clients/repository";
import type { Client, ClientAuthMethodName } from "../clients/types";
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS
} from "../clients/types";
import type { SigningKeySigner } from "../keys/signer";
import type { ResolvedIssuerContext } from "../tenants/types";
import type { UserRepository } from "../users/repository";
import type { User } from "../users/types";
import { sha256Base64Url } from "../../lib/hash";
import { buildAccessTokenClaims, buildIdTokenClaims } from "./claims";
import type { OidcTokenErrorResponse, OidcTokenSuccessResponse } from "../oidc/token-response";
import type {
  RefreshTokenRecord,
  RefreshTokenRepository
} from "./refresh-token-repository";
import type { AccessTokenRevocationRepository } from "./access-token-revocation-repository";
import {
  computeContentReaderTtlSeconds,
  isContentReaderIdentity,
  isContentReaderIssuanceAllowed,
  mergeContentReaderClaims,
  type ContentReaderIssuancePolicy
} from "./content-reader-policy";

type TokenErrorCode = OidcTokenErrorResponse["error"];

export type ScopeTokenErrorCode =
  | "invalid_client"
  | "invalid_grant"
  | "invalid_request"
  | "invalid_scope"
  | "invalid_lifetime"
  | "temporarily_unavailable"
  | "server_error";

export interface ScopeTokenSuccessResponse {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: "Bearer";
}

export interface ScopeTokenRequest {
  authorizationHeader: string | undefined;
  claims: unknown;
  requestedClientId: string | null;
  requestedClientSecret: string | null;
  subjectToken: string;
}

export interface TokenRevokeRequest {
  authorizationHeader: string | undefined;
  requestedClientId: string | null;
  requestedClientSecret: string | null;
  token: string;
}

export interface TokenIntrospectionRequest {
  authorizationHeader: string | undefined;
  requestedClientId: string | null;
  requestedClientSecret: string | null;
  token: string;
}

export type TokenRevokeResult =
  | { kind: "success"; clientId: string }
  | { kind: "error"; clientId: string | null; error: "invalid_client"; status: 401 };

export type TokenIntrospectionResult =
  | { kind: "success"; active: boolean }
  | { kind: "error"; error: "invalid_client"; status: 401 };

type ScopeTokenErrorResult = {
  kind: "error";
  clientId: string | null;
  error: ScopeTokenErrorCode;
  mode: "workspace" | "content_reader" | null;
  status: 400 | 401 | 503;
  tenantId: string | null;
  userId: string | null;
  workspaceId?: string | null;
  entitlementRevision?: string | null;
  contentDatabase?: string | null;
};

type ScopeTokenSuccessResult = {
  kind: "success";
  clientId: string;
  mode: "workspace" | "content_reader";
  response: ScopeTokenSuccessResponse;
  tenantId: string;
  userId: string;
  workspaceId?: string | null;
  entitlementRevision?: string | null;
  contentDatabase?: string | null;
};

export type ScopeTokenResult = ScopeTokenErrorResult | ScopeTokenSuccessResult;

type WorkspaceScopeClaims = {
  mode: "workspace";
  claims: Record<string, unknown>;
};

type ContentReaderScopeClaims = {
  mode: "content_reader";
  claims: {
    ac: "content_reader";
    db: string;
    workspace_id: string;
    entitlement_revision: string;
    lease_end: number;
  };
};

type NormalizedScopeClaims = WorkspaceScopeClaims | ContentReaderScopeClaims;

type ClientCredentials =
  | { kind: "basic"; clientId: string; clientSecret: string }
  | { kind: "post"; clientId: string; clientSecret: string | null };

export interface TokenExchangeRequest {
  authorizationHeader: string | undefined;
  code: string;
  codeVerifier: string;
  grantType: string;
  refreshToken: string | null;
  redirectUri: string;
  resource?: string | null;
  requestedClientId: string | null;
  requestedClientSecret: string | null;
}

type TokenExchangeErrorResult = {
  kind: "error";
  clientId: string | null;
  error: TokenErrorCode;
  status: 400 | 401;
};

type TokenExchangeSuccessResult = {
  kind: "success";
  clientId: string;
  response: OidcTokenSuccessResponse;
  tenantId: string;
  userId: string;
};

export type TokenExchangeResult = TokenExchangeErrorResult | TokenExchangeSuccessResult;

const parseBasicAuthorization = (
  authorizationHeader: string | undefined
): ClientCredentials | "invalid" | null => {
  if (authorizationHeader === undefined) {
    return null;
  }

  const basicPrefixMatch = authorizationHeader.match(/^basic\s+/iu);

  if (basicPrefixMatch === null) {
    return "invalid";
  }

  const encoded = authorizationHeader.slice(basicPrefixMatch[0].length).trim();

  if (encoded.length === 0) {
    return "invalid";
  }

  try {
    const decoded = atob(encoded);
    const separatorIndex = decoded.indexOf(":");

    if (separatorIndex <= 0) {
      return "invalid";
    }

    const clientId = decoded.slice(0, separatorIndex);
    const clientSecret = decoded.slice(separatorIndex + 1);

    return {
      kind: "basic",
      clientId,
      clientSecret
    };
  } catch {
    return "invalid";
  }
};

const authenticateClient = async ({
  authorizationHeader,
  clientRepository,
  issuerContext,
  requireClientSecret = false,
  requestedClientId,
  requestedClientSecret
}: {
  authorizationHeader: string | undefined;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  requireClientSecret?: boolean;
  requestedClientId: string | null;
  requestedClientSecret: string | null;
}): Promise<
  | { ok: true; client: Client }
  | { ok: false; clientId: string | null; error: TokenErrorCode; status: 401 }
> => {
  const basicCredentials = parseBasicAuthorization(authorizationHeader);

  if (basicCredentials === "invalid") {
    return {
      ok: false,
      clientId: null,
      error: "invalid_client",
      status: 401
    };
  }

  const hasBodyCredentials = requestedClientId !== null;
  const credentials: ClientCredentials | null =
    basicCredentials !== null
      ? basicCredentials
      : hasBodyCredentials
        ? {
            kind: "post",
            clientId: requestedClientId,
            clientSecret: requestedClientSecret
          }
        : null;

  if (credentials === null || credentials.clientId.trim().length === 0) {
    return {
      ok: false,
      clientId: null,
      error: "invalid_client",
      status: 401
    };
  }

  if (basicCredentials !== null && hasBodyCredentials) {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  const client = await clientRepository.findByClientId(credentials.clientId);

  if (client === null || client.tenantId !== issuerContext.tenant.id) {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  if (client.tokenEndpointAuthMethod === "none") {
    if (requireClientSecret) {
      return {
        ok: false,
        clientId: credentials.clientId,
        error: "invalid_client",
        status: 401
      };
    }

    if (credentials.kind !== "post" || credentials.clientSecret !== null) {
      return {
        ok: false,
        clientId: credentials.clientId,
        error: "invalid_client",
        status: 401
      };
    }

    return {
      ok: true,
      client
    };
  }

  if (client.tokenEndpointAuthMethod === "client_secret_basic" && credentials.kind !== "basic") {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  if (client.tokenEndpointAuthMethod === "client_secret_post" && credentials.kind !== "post") {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  if (credentials.clientSecret === null || client.clientSecretHash === null) {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  if ((await sha256Base64Url(credentials.clientSecret)) !== client.clientSecretHash) {
    return {
      ok: false,
      clientId: credentials.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  return {
    ok: true,
    client
  };
};

const createSignedJwt = async ({
  claims,
  signer,
  tenantId
}: {
  claims: Record<string, unknown>;
  signer: SigningKeySigner;
  tenantId: string;
}) => {
  const signingKeyMaterial = await signer.ensureActiveSigningKeyMaterial(tenantId);
  const privateKey = await importJWK(signingKeyMaterial.privateJwk, signingKeyMaterial.key.alg);

  return await new SignJWT(claims)
    .setProtectedHeader({
      alg: signingKeyMaterial.key.alg,
      kid: signingKeyMaterial.key.kid,
      typ: "JWT"
    })
    .sign(privateKey);
};

const verifyTenantAccessToken = async ({
  issuerContext,
  signer,
  tenantId,
  token
}: {
  issuerContext: ResolvedIssuerContext;
  signer: SigningKeySigner | undefined;
  tenantId: string;
  token: string;
}): Promise<Record<string, unknown> | null> => {
  if (signer === undefined) return null;

  const signingKeyMaterial = await signer.loadActiveSigningKeyMaterial(tenantId);
  if (signingKeyMaterial === null) return null;

  try {
    const publicKey = await importJWK(
      signingKeyMaterial.key.publicJwk,
      signingKeyMaterial.key.alg
    );
    const verification = await jwtVerify(token, publicKey, {
      issuer: issuerContext.issuer
    });
    return verification.payload as Record<string, unknown>;
  } catch {
    return null;
  }
};

const mutableWorkspaceScopeClaimNames = new Map([
  ["db", "db"],
  ["ac", "ac"],
  ["email", "email"],
  ["RL", "RL"]
]);

const contentReaderScopeClaimNames = new Set([
  "ac",
  "db",
  "workspace_id",
  "entitlement_revision",
  "lease_end"
]);

const surrealDbRoleClaimValues = new Set(["Viewer", "Editor", "Owner"]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const normalizeSurrealDbRoleClaims = (value: unknown): string[] | null => {
  if (!Array.isArray(value) || value.length === 0 || value.length > surrealDbRoleClaimValues.size) {
    return null;
  }

  const roles: string[] = [];
  const seen = new Set<string>();

  for (const role of value) {
    if (
      typeof role !== "string" ||
      !surrealDbRoleClaimValues.has(role) ||
      seen.has(role)
    ) {
      return null;
    }

    roles.push(role);
    seen.add(role);
  }

  return roles;
};

const normalizeContentReaderScopeClaims = (
  input: Record<string, unknown>
): { ok: true; value: ContentReaderScopeClaims } | { ok: false } => {
  const keys = Object.keys(input);

  if (keys.length !== contentReaderScopeClaimNames.size) {
    return { ok: false };
  }

  for (const key of keys) {
    if (!contentReaderScopeClaimNames.has(key)) {
      return { ok: false };
    }
  }

  const ac = input.ac;
  const db = input.db;
  const workspaceId = input.workspace_id;
  const entitlementRevision = input.entitlement_revision;
  const leaseEnd = input.lease_end;

  if (ac !== "content_reader") {
    return { ok: false };
  }

  if (typeof db !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(db)) {
    return { ok: false };
  }

  if (!isContentReaderIdentity(workspaceId) || !isContentReaderIdentity(entitlementRevision)) {
    return { ok: false };
  }

  if (typeof leaseEnd !== "number" || !Number.isInteger(leaseEnd)) {
    return { ok: false };
  }

  return {
    ok: true,
    value: {
      mode: "content_reader",
      claims: {
        ac: "content_reader",
        db,
        workspace_id: workspaceId,
        entitlement_revision: entitlementRevision,
        lease_end: leaseEnd
      }
    }
  };
};

const normalizeWorkspaceScopeClaims = (
  input: Record<string, unknown>
): { ok: true; value: WorkspaceScopeClaims } | { ok: false } => {
  const claims: Record<string, unknown> = {};

  for (const [claimName, value] of Object.entries(input)) {
    const normalizedClaimName = mutableWorkspaceScopeClaimNames.get(claimName);

    if (normalizedClaimName === undefined || normalizedClaimName in claims) {
      return { ok: false };
    }

    if (normalizedClaimName === "db") {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
        return { ok: false };
      }

      claims[normalizedClaimName] = value;
      continue;
    }

    if (normalizedClaimName === "ac") {
      if (value !== "admin" && value !== "participant") {
        return { ok: false };
      }

      claims[normalizedClaimName] = value;
      continue;
    }

    if (normalizedClaimName === "email") {
      if (
        typeof value !== "string" ||
        value.length > 320 ||
        !/^[^\s@]+@[^\s@]+$/.test(value)
      ) {
        return { ok: false };
      }

      claims[normalizedClaimName] = value;
      continue;
    }

    if (normalizedClaimName === "RL") {
      const roles = normalizeSurrealDbRoleClaims(value);

      if (roles === null) {
        return { ok: false };
      }

      claims[normalizedClaimName] = roles;
      continue;
    }

    return { ok: false };
  }

  return Object.keys(claims).length === 0
    ? { ok: false }
    : { ok: true, value: { mode: "workspace", claims } };
};

const normalizeScopeClaims = (
  input: unknown
): { ok: true; value: NormalizedScopeClaims } | { ok: false } => {
  if (!isRecord(input)) {
    return { ok: false };
  }

  if (input.ac === "content_reader") {
    return normalizeContentReaderScopeClaims(input);
  }

  return normalizeWorkspaceScopeClaims(input);
};

const resolveSubjectTokenAudience = (payload: Record<string, unknown>): string | null => {
  const audience = payload.aud;

  if (typeof audience === "string" && audience.length > 0) {
    return audience;
  }

  if (Array.isArray(audience)) {
    const values = audience.filter(
      (value): value is string => typeof value === "string" && value.length > 0
    );
    return values.length === 1 ? values[0]! : null;
  }

  return null;
};

const resolveConfiguredAccessTokenClaims = async ({
  accessTokenClaimsRepository,
  claimHookFetcher,
  client,
  tenantId,
  user,
  userRepository,
  userId
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  claimHookFetcher?: ClaimHookFetcher;
  client: Client;
  tenantId: string;
  user?: User;
  userRepository: UserRepository;
  userId: string;
}): Promise<Record<string, unknown> | null> => {
  const customClaimConfigs = await accessTokenClaimsRepository.listByClientIdAndTenantId(
    client.id,
    tenantId
  );

  if (customClaimConfigs.length === 0) {
    return {};
  }

  const resolvedUser = user ?? (await userRepository.findUserById(tenantId, userId));

  if (resolvedUser === null) {
    return null;
  }

  const claimHook: ResolveCustomClaimsHookDeps | undefined =
    client.claimHookUrl !== undefined &&
    client.claimHookUrl !== null &&
    client.claimHookUrl !== ""
      ? {
          config: {
            url: client.claimHookUrl,
            authHeaderName: client.claimHookAuthHeaderName ?? null,
            authHeaderValue: client.claimHookAuthHeaderValue ?? null
          },
          ...(claimHookFetcher === undefined ? {} : { fetcher: claimHookFetcher })
        }
      : undefined;

  return await resolveCustomClaims(customClaimConfigs, resolvedUser, claimHook);
};

export const issueClientAccessToken = async ({
  client,
  extraClaims = {},
  issuer,
  now = new Date(),
  scope,
  signer,
  subject,
  tenantId,
  ttlSeconds = DEFAULT_TOKEN_TTL_SECONDS,
  username
}: {
  client: Client;
  extraClaims?: Record<string, unknown>;
  issuer: string;
  now?: Date;
  scope: string;
  signer: SigningKeySigner;
  subject: string;
  tenantId: string;
  ttlSeconds?: number;
  username?: string;
}): Promise<string> => {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const resolvedAudience = client.accessTokenAudience ?? client.clientId;
  const accessTokenClaims = buildAccessTokenClaims({
    audience: resolvedAudience,
    clientId: client.clientId,
    extraClaims: {
      ...extraClaims,
      ...(username === undefined ? {} : { username })
    },
    issuer,
    nowSeconds,
    scope,
    tokenId: crypto.randomUUID(),
    ttlSeconds,
    userId: subject
  });

  return await createSignedJwt({
    claims: accessTokenClaims,
    signer,
    tenantId
  });
};

const resolveTokenTtlSeconds = async ({
  authMethod,
  client,
  clientAuthMethodPolicyRepository
}: {
  authMethod: ClientAuthMethodName | null | undefined;
  client: Client;
  clientAuthMethodPolicyRepository: ClientAuthMethodPolicyRepository;
}) => {
  if (authMethod == null) {
    return DEFAULT_TOKEN_TTL_SECONDS;
  }

  const policy = await clientAuthMethodPolicyRepository.findByClientId(client.id);

  if (policy === null) {
    return DEFAULT_TOKEN_TTL_SECONDS;
  }

  switch (authMethod) {
    case "password":
      return policy.password.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "magic_link":
      return policy.emailMagicLink.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "passkey":
      return policy.passkey.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "google":
      return policy.google.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "apple":
      return policy.apple.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "facebook":
      return policy.facebook.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    case "wechat":
      return policy.wechat.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  }
};

const issueRefreshToken = async ({
  authMethod,
  client,
  issuer,
  now,
  refreshTokenRepository,
  resource,
  scope,
  tenantId,
  userId
}: {
  authMethod: ClientAuthMethodName | null;
  client: Client;
  issuer: string;
  now: Date;
  refreshTokenRepository: RefreshTokenRepository;
  resource: string | null;
  scope: string;
  tenantId: string;
  userId: string;
}) => {
  const refreshToken = crypto.randomUUID().replaceAll("-", "");
  const refreshTokenRecord: RefreshTokenRecord = {
    id: crypto.randomUUID(),
    tenantId,
    issuer,
    clientId: client.clientId,
    userId,
    scope,
    resource,
    authMethod,
    tokenHash: await sha256Base64Url(refreshToken),
    absoluteExpiresAt: new Date(
      now.getTime() + REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS * 1000
    ).toISOString(),
    consumedAt: null,
    parentTokenId: null,
    replacedByTokenId: null,
    createdAt: now.toISOString()
  };

  await refreshTokenRepository.create(refreshTokenRecord);

  return {
    refreshToken,
    record: refreshTokenRecord
  };
};

const issueTokenSet = async ({
  accessTokenClaimsRepository,
  client,
  clientAuthMethodPolicyRepository,
  issuer,
  refreshTokenRepository,
  resource,
  scope,
  signer,
  tenantId,
  userId,
  authMethod,
  nonce,
  now,
  userRepository,
  claimHookFetcher
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  client: Client;
  clientAuthMethodPolicyRepository: ClientAuthMethodPolicyRepository;
  issuer: string;
  refreshTokenRepository: RefreshTokenRepository;
  resource: string | null;
  scope: string;
  signer: SigningKeySigner;
  tenantId: string;
  userId: string;
  authMethod: ClientAuthMethodName | null | undefined;
  nonce: string | null;
  now: Date;
  userRepository: UserRepository;
  claimHookFetcher?: ClaimHookFetcher;
}): Promise<OidcTokenSuccessResponse | null> => {
  const extraClaims = await resolveConfiguredAccessTokenClaims({
    accessTokenClaimsRepository,
    client,
    tenantId,
    userRepository,
    userId,
    claimHookFetcher
  });

  if (extraClaims === null) {
    return null;
  }

  const ttlSeconds = await resolveTokenTtlSeconds({
    authMethod,
    client,
    clientAuthMethodPolicyRepository
  });
  const resolvedAudience = resource ?? client.accessTokenAudience ?? client.clientId;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const idTokenClaims = buildIdTokenClaims({
    audience: client.clientId,
    issuer,
    nonce,
    nowSeconds,
    scope,
    tokenId: crypto.randomUUID(),
    ttlSeconds,
    userId
  });
  const accessTokenClaims = buildAccessTokenClaims({
    audience: resolvedAudience,
    clientId: client.clientId,
    extraClaims,
    issuer,
    nowSeconds,
    scope,
    tokenId: crypto.randomUUID(),
    ttlSeconds,
    userId
  });
  const [idToken, accessToken, refresh] = await Promise.all([
    createSignedJwt({
      claims: idTokenClaims,
      signer,
      tenantId
    }),
    createSignedJwt({
      claims: accessTokenClaims,
      signer,
      tenantId
    }),
    issueRefreshToken({
      authMethod: authMethod ?? null,
      client,
      issuer,
      now,
      refreshTokenRepository,
      resource,
      scope,
      tenantId,
      userId
    })
  ]);

  return {
    token_type: "Bearer",
    expires_in: ttlSeconds,
    access_token: accessToken,
    id_token: idToken,
    refresh_token: refresh.refreshToken,
    scope
  };
};

export const issueScopeToken = async ({
  accessTokenClaimsRepository,
  clientRepository,
  contentReaderPolicy,
  issuerContext,
  request,
  signer,
  userRepository,
  claimHookFetcher
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientRepository: ClientRepository;
  contentReaderPolicy?: ContentReaderIssuancePolicy | null;
  issuerContext: ResolvedIssuerContext;
  request: ScopeTokenRequest;
  signer: SigningKeySigner | undefined;
  userRepository: UserRepository;
  claimHookFetcher?: ClaimHookFetcher;
}): Promise<ScopeTokenResult> => {
  const normalizedClaims = normalizeScopeClaims(request.claims);

  if (!normalizedClaims.ok || request.subjectToken.trim().length === 0) {
    return {
      kind: "error",
      clientId: null,
      error: "invalid_request",
      mode: null,
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  const scopeMode = normalizedClaims.value.mode;

  const authenticatedClient = await authenticateClient({
    authorizationHeader: request.authorizationHeader,
    clientRepository,
    issuerContext,
    requestedClientId: request.requestedClientId,
    requestedClientSecret: request.requestedClientSecret,
    requireClientSecret: true
  });

  if (!authenticatedClient.ok) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
      error: "invalid_client",
      mode: scopeMode,
      status: 401,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  if (signer === undefined) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: scopeMode === "content_reader" ? "temporarily_unavailable" : "server_error",
      mode: scopeMode,
      status: 503,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  const signingKeyMaterial = await signer.loadActiveSigningKeyMaterial(issuerContext.tenant.id);

  if (signingKeyMaterial === null) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: scopeMode === "content_reader" ? "temporarily_unavailable" : "server_error",
      mode: scopeMode,
      status: 503,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  let payload: Record<string, unknown>;
  try {
    const publicKey = await importJWK(
      signingKeyMaterial.key.publicJwk,
      signingKeyMaterial.key.alg
    );
    const verification = await jwtVerify(request.subjectToken, publicKey, {
      issuer: issuerContext.issuer
    });
    payload = verification.payload as Record<string, unknown>;
  } catch {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      mode: scopeMode,
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  const clientId = typeof payload.client_id === "string" ? payload.client_id : null;
  const userId = typeof payload.sub === "string" ? payload.sub : null;
  const scope = typeof payload.scope === "string" ? payload.scope : null;
  const expiresAt = typeof payload.exp === "number" ? payload.exp : null;
  const subjectAudience = resolveSubjectTokenAudience(payload);
  const expectedAudience =
    authenticatedClient.client.accessTokenAudience ?? authenticatedClient.client.clientId;

  if (
    clientId === null ||
    clientId !== authenticatedClient.client.clientId ||
    userId === null ||
    scope === null ||
    expiresAt === null ||
    subjectAudience === null ||
    subjectAudience !== expectedAudience
  ) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      mode: scopeMode,
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId
    };
  }

  // content_reader credentials are not an elevation path into workspace or publisher scopes.
  if (payload.ac === "content_reader") {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_scope",
      mode: scopeMode,
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId
    };
  }

  const client = authenticatedClient.client;

  const user = await userRepository.findUserById(issuerContext.tenant.id, userId);

  if (user === null || user.status !== "active") {
    return {
      kind: "error",
      clientId,
      error: "invalid_grant",
      mode: scopeMode,
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId
    };
  }

  if (scopeMode === "workspace") {
    const workspaceClaims = normalizedClaims.value.claims;

    if (
      typeof workspaceClaims.email === "string" &&
      workspaceClaims.email !== user.email
    ) {
      return {
        kind: "error",
        clientId,
        error: "invalid_request",
        mode: scopeMode,
        status: 400,
        tenantId: issuerContext.tenant.id,
        userId
      };
    }

    const configuredClaims = await resolveConfiguredAccessTokenClaims({
      accessTokenClaimsRepository,
      client,
      tenantId: issuerContext.tenant.id,
      user,
      userRepository,
      userId,
      claimHookFetcher
    });

    if (configuredClaims === null) {
      return {
        kind: "error",
        clientId,
        error: "server_error",
        mode: scopeMode,
        status: 503,
        tenantId: issuerContext.tenant.id,
        userId
      };
    }

    const now = new Date();
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const ttlSeconds = expiresAt - nowSeconds;

    if (ttlSeconds <= 0) {
      return {
        kind: "error",
        clientId,
        error: "invalid_grant",
        mode: scopeMode,
        status: 400,
        tenantId: issuerContext.tenant.id,
        userId
      };
    }

    try {
      // Merge order: configured (fixed → user_field → hook) then request claims overlay.
      const accessToken = await issueClientAccessToken({
        client,
        extraClaims: {
          ...configuredClaims,
          ...workspaceClaims
        },
        issuer: issuerContext.issuer,
        now,
        scope,
        signer,
        subject: userId,
        tenantId: issuerContext.tenant.id,
        ttlSeconds
      });

      return {
        kind: "success",
        clientId,
        mode: "workspace",
        tenantId: issuerContext.tenant.id,
        userId,
        response: {
          access_token: accessToken,
          expires_in: ttlSeconds,
          scope,
          token_type: "Bearer"
        }
      };
    } catch {
      return {
        kind: "error",
        clientId,
        error: "server_error",
        mode: scopeMode,
        status: 503,
        tenantId: issuerContext.tenant.id,
        userId
      };
    }
  }

  const contentClaims = normalizedClaims.value.claims;

  if (
    !isContentReaderIssuanceAllowed({
      clientId: client.clientId,
      policy: contentReaderPolicy,
      tenantId: issuerContext.tenant.id
    })
  ) {
    return {
      kind: "error",
      clientId,
      error: "invalid_scope",
      mode: "content_reader",
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db
    };
  }

  const policy = contentReaderPolicy!;

  if (!policy.allowedContentDatabases.includes(contentClaims.db)) {
    return {
      kind: "error",
      clientId,
      error: "invalid_scope",
      mode: "content_reader",
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db
    };
  }

  const now = new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const ttl = computeContentReaderTtlSeconds({
    leaseEndSeconds: contentClaims.lease_end,
    maxTtlSeconds: policy.maxTtlSeconds,
    nowSeconds,
    subjectExpiresAt: expiresAt
  });

  if (!ttl.ok) {
    return {
      kind: "error",
      clientId,
      error: "invalid_lifetime",
      mode: "content_reader",
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db
    };
  }

  const configuredClaims = await resolveConfiguredAccessTokenClaims({
    accessTokenClaimsRepository,
    client,
    tenantId: issuerContext.tenant.id,
    user,
    userRepository,
    userId,
    claimHookFetcher
  });

  if (configuredClaims === null) {
    return {
      kind: "error",
      clientId,
      error: "temporarily_unavailable",
      mode: "content_reader",
      status: 503,
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db
    };
  }

  try {
    const accessToken = await issueClientAccessToken({
      client,
      extraClaims: mergeContentReaderClaims({
        configuredClaims,
        contentClaims: {
          ac: contentClaims.ac,
          db: contentClaims.db,
          workspace_id: contentClaims.workspace_id,
          entitlement_revision: contentClaims.entitlement_revision
        }
      }),
      issuer: issuerContext.issuer,
      now,
      scope,
      signer,
      subject: userId,
      tenantId: issuerContext.tenant.id,
      ttlSeconds: ttl.ttlSeconds
    });

    return {
      kind: "success",
      clientId,
      mode: "content_reader",
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db,
      response: {
        access_token: accessToken,
        expires_in: ttl.ttlSeconds,
        scope,
        token_type: "Bearer"
      }
    };
  } catch {
    return {
      kind: "error",
      clientId,
      error: "temporarily_unavailable",
      mode: "content_reader",
      status: 503,
      tenantId: issuerContext.tenant.id,
      userId,
      workspaceId: contentClaims.workspace_id,
      entitlementRevision: contentClaims.entitlement_revision,
      contentDatabase: contentClaims.db
    };
  }
};

export const exchangeAuthorizationCode = async ({
  authorizationCodeRepository,
  accessTokenClaimsRepository,
  clientAuthMethodPolicyRepository,
  clientRepository,
  issuerContext,
  refreshTokenRepository,
  request,
  signer,
  userRepository,
  claimHookFetcher
}: {
  authorizationCodeRepository: AuthorizationCodeRepository;
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientAuthMethodPolicyRepository: ClientAuthMethodPolicyRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  refreshTokenRepository: RefreshTokenRepository;
  request: TokenExchangeRequest;
  signer: SigningKeySigner | undefined;
  userRepository: UserRepository;
  claimHookFetcher?: ClaimHookFetcher;
}): Promise<TokenExchangeResult> => {
  const authenticatedClient = await authenticateClient({
    authorizationHeader: request.authorizationHeader,
    clientRepository,
    issuerContext,
    requestedClientId: request.requestedClientId,
    requestedClientSecret: request.requestedClientSecret
  });

  if (!authenticatedClient.ok) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
      error: authenticatedClient.error,
      status: authenticatedClient.status
    };
  }

  if (request.grantType === "refresh_token") {
    if (request.refreshToken === null || request.refreshToken.trim().length === 0) {
      return {
        kind: "error",
        clientId: authenticatedClient.client.clientId,
        error: "invalid_request",
        status: 400
      };
    }

    if (signer === undefined) {
      return {
        kind: "error",
        clientId: authenticatedClient.client.clientId,
        error: "server_error",
        status: 400
      };
    }

    const now = new Date();
    const refreshTokenRecord = await refreshTokenRepository.findActiveByTokenHash(
      await sha256Base64Url(request.refreshToken)
    );

    if (
      refreshTokenRecord === null ||
      refreshTokenRecord.clientId !== authenticatedClient.client.clientId ||
      refreshTokenRecord.tenantId !== authenticatedClient.client.tenantId ||
      refreshTokenRecord.issuer !== issuerContext.issuer ||
      new Date(refreshTokenRecord.absoluteExpiresAt).getTime() <= now.getTime()
    ) {
      return {
        kind: "error",
        clientId: authenticatedClient.client.clientId,
        error: "invalid_grant",
        status: 400
      };
    }

    const refreshResource = refreshTokenRecord?.resource ?? null;
    if (
      (request.resource !== undefined &&
        request.resource !== null &&
        request.resource !== refreshResource) ||
      (refreshResource !== null && refreshResource !== authenticatedClient.client.accessTokenAudience)
    ) {
      return {
        kind: "error",
        clientId: authenticatedClient.client.clientId,
        error: "invalid_grant",
        status: 400
      };
    }

    try {
      const tokenSet = await issueTokenSet({
        accessTokenClaimsRepository,
        client: authenticatedClient.client,
        clientAuthMethodPolicyRepository,
        issuer: issuerContext.issuer,
        refreshTokenRepository,
        resource: refreshResource,
        scope: refreshTokenRecord.scope,
        signer,
        tenantId: refreshTokenRecord.tenantId,
        userId: refreshTokenRecord.userId,
        authMethod: refreshTokenRecord.authMethod,
        nonce: null,
        now,
        userRepository,
        claimHookFetcher
      });

      if (tokenSet === null) {
        return {
          kind: "error",
          clientId: authenticatedClient.client.clientId,
          error: "server_error",
          status: 400
        };
      }

      const replacementTokenHash = await sha256Base64Url(tokenSet.refresh_token ?? "");
      const replacementRecord = await refreshTokenRepository.findActiveByTokenHash(
        replacementTokenHash
      );

      const consumed = await refreshTokenRepository.consume(
        refreshTokenRecord.id,
        now.toISOString(),
        replacementRecord?.id ?? null
      );

      if (!consumed) {
        return {
          kind: "error",
          clientId: authenticatedClient.client.clientId,
          error: "invalid_grant",
          status: 400
        };
      }

      return {
        kind: "success",
        clientId: authenticatedClient.client.clientId,
        tenantId: refreshTokenRecord.tenantId,
        userId: refreshTokenRecord.userId,
        response: tokenSet
      };
    } catch {
      return {
        kind: "error",
        clientId: authenticatedClient.client.clientId,
        error: "server_error",
        status: 400
      };
    }
  }

  if (request.grantType !== "authorization_code") {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "unsupported_grant_type",
      status: 400
    };
  }

  if (request.code.length === 0 || request.codeVerifier.length === 0 || request.redirectUri.length === 0) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_request",
      status: 400
    };
  }

  const now = new Date();
  const codeRecord = await authorizationCodeRepository.findByTokenHash(
    await sha256Base64Url(request.code)
  );

  if (codeRecord === null) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  if (
    codeRecord.clientId !== authenticatedClient.client.clientId ||
    codeRecord.tenantId !== authenticatedClient.client.tenantId ||
    codeRecord.issuer !== issuerContext.issuer ||
    codeRecord.redirectUri !== request.redirectUri ||
    new Date(codeRecord.expiresAt).getTime() <= now.getTime() ||
    (request.resource !== undefined &&
      request.resource !== null &&
      request.resource !== (codeRecord.resource ?? null)) ||
    ((codeRecord.resource ?? null) !== null &&
      codeRecord.resource !== authenticatedClient.client.accessTokenAudience)
  ) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  const pkceMatches = await verifyPkce({
    codeChallenge: codeRecord.codeChallenge,
    codeChallengeMethod: codeRecord.codeChallengeMethod,
    codeVerifier: request.codeVerifier
  });

  if (!pkceMatches) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  const consumed = await authorizationCodeRepository.consumeById(codeRecord.id, now.toISOString());

  if (!consumed) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  if (signer === undefined) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "server_error",
      status: 400
    };
  }

  try {
    const client = authenticatedClient.client;
    const response = await issueTokenSet({
      accessTokenClaimsRepository,
      client,
      clientAuthMethodPolicyRepository,
      issuer: issuerContext.issuer,
      refreshTokenRepository,
      resource: codeRecord.resource ?? null,
      scope: codeRecord.scope,
      signer,
      tenantId: codeRecord.tenantId,
      userId: codeRecord.userId,
      authMethod: codeRecord.authMethod ?? null,
      nonce: codeRecord.nonce,
      now,
      userRepository,
      claimHookFetcher
    });

    if (response === null) {
      return {
        kind: "error",
        clientId: client.clientId,
        error: "server_error",
        status: 400
      };
    }

    return {
      kind: "success",
      clientId: client.clientId,
      tenantId: codeRecord.tenantId,
      userId: codeRecord.userId,
      response
    };
  } catch {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "server_error",
      status: 400
    };
  }
};

/** RFC 7009-style refresh-token revocation. Unknown or already consumed
 * tokens are deliberately treated as success to avoid token-existence leaks. */
export const revokeToken = async ({
  accessTokenRevocationRepository,
  clientRepository,
  issuerContext,
  refreshTokenRepository,
  request,
  signer
}: {
  accessTokenRevocationRepository: AccessTokenRevocationRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  refreshTokenRepository: RefreshTokenRepository;
  request: TokenRevokeRequest;
  signer: SigningKeySigner | undefined;
}): Promise<TokenRevokeResult> => {
  const authenticatedClient = await authenticateClient({
    authorizationHeader: request.authorizationHeader,
    clientRepository,
    issuerContext,
    requestedClientId: request.requestedClientId,
    requestedClientSecret: request.requestedClientSecret
  });

  if (!authenticatedClient.ok) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
      error: "invalid_client",
      status: 401
    };
  }

  const token = request.token.trim();
  if (token.length > 0) {
    const record = await refreshTokenRepository.findActiveByTokenHash(
      await sha256Base64Url(token)
    );
    if (
      record !== null &&
      record.clientId === authenticatedClient.client.clientId &&
      record.tenantId === authenticatedClient.client.tenantId &&
      record.issuer === issuerContext.issuer
    ) {
      await refreshTokenRepository.consume(record.id, new Date().toISOString(), null);
    } else {
      const payload = await verifyTenantAccessToken({
        issuerContext,
        signer,
        tenantId: authenticatedClient.client.tenantId,
        token
      });
      const tokenClientId = typeof payload?.client_id === "string" ? payload.client_id : null;
      const expiresAtSeconds = typeof payload?.exp === "number" ? payload.exp : null;

      if (tokenClientId === authenticatedClient.client.clientId && expiresAtSeconds !== null) {
        await accessTokenRevocationRepository.revoke({
          id: crypto.randomUUID(),
          tenantId: authenticatedClient.client.tenantId,
          clientId: tokenClientId,
          tokenHash: await sha256Base64Url(token),
          expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
          revokedAt: new Date().toISOString()
        });
      }
    }
  }

  return { kind: "success", clientId: authenticatedClient.client.clientId };
};

/** RFC 7662-style minimal response for resource servers. */
export const introspectAccessToken = async ({
  accessTokenRevocationRepository,
  clientRepository,
  issuerContext,
  request,
  signer
}: {
  accessTokenRevocationRepository: AccessTokenRevocationRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  request: TokenIntrospectionRequest;
  signer: SigningKeySigner | undefined;
}): Promise<TokenIntrospectionResult> => {
  const authenticatedClient = await authenticateClient({
    authorizationHeader: request.authorizationHeader,
    clientRepository,
    issuerContext,
    requestedClientId: request.requestedClientId,
    requestedClientSecret: request.requestedClientSecret,
    requireClientSecret: true
  });

  if (!authenticatedClient.ok) {
    return { kind: "error", error: "invalid_client", status: 401 };
  }

  const token = request.token.trim();
  if (token.length === 0) return { kind: "success", active: false };

  const payload = await verifyTenantAccessToken({
    issuerContext,
    signer,
    tenantId: authenticatedClient.client.tenantId,
    token
  });
  if (payload === null || typeof payload.client_id !== "string") {
    return { kind: "success", active: false };
  }

  return {
    kind: "success",
    active: !(await accessTokenRevocationRepository.isRevoked(await sha256Base64Url(token)))
  };
};
