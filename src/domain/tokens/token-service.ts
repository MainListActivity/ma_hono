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

type TokenErrorCode = OidcTokenErrorResponse["error"];

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

type ScopeTokenErrorResult = {
  kind: "error";
  clientId: string | null;
  error: "invalid_client" | "invalid_grant" | "invalid_request" | "server_error";
  status: 400 | 401 | 503;
  tenantId: string | null;
  userId: string | null;
};

type ScopeTokenSuccessResult = {
  kind: "success";
  clientId: string;
  response: ScopeTokenSuccessResponse;
  tenantId: string;
  userId: string;
};

export type ScopeTokenResult = ScopeTokenErrorResult | ScopeTokenSuccessResult;

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

const mutableScopeClaimNames = new Map([
  ["db", "db"],
  ["ac", "ac"],
  ["email", "email"],
  ["RL", "RL"]
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

const normalizeScopeClaims = (
  input: unknown
): { ok: true; claims: Record<string, unknown> } | { ok: false } => {
  if (!isRecord(input)) {
    return { ok: false };
  }

  const claims: Record<string, unknown> = {};

  for (const [claimName, value] of Object.entries(input)) {
    const normalizedClaimName = mutableScopeClaimNames.get(claimName);

    if (normalizedClaimName === undefined || normalizedClaimName in claims) {
      return { ok: false };
    }

    if (normalizedClaimName === "db") {
      if (
        typeof value !== "string" ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(value)
      ) {
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

  return Object.keys(claims).length === 0 ? { ok: false } : { ok: true, claims };
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
  scope,
  tenantId,
  userId
}: {
  authMethod: ClientAuthMethodName | null;
  client: Client;
  issuer: string;
  now: Date;
  refreshTokenRepository: RefreshTokenRepository;
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
  const resolvedAudience = client.accessTokenAudience ?? client.clientId;
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
  issuerContext,
  request,
  signer,
  userRepository,
  claimHookFetcher
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  request: ScopeTokenRequest;
  signer: SigningKeySigner | undefined;
  userRepository: UserRepository;
  claimHookFetcher?: ClaimHookFetcher;
}): Promise<ScopeTokenResult> => {
  const mutableClaims = normalizeScopeClaims(request.claims);

  if (!mutableClaims.ok || request.subjectToken.trim().length === 0) {
    return {
      kind: "error",
      clientId: null,
      error: "invalid_request",
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

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
      status: 401,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  if (signer === undefined) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "server_error",
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
      error: "server_error",
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
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId: null
    };
  }

  const clientId = typeof payload.client_id === "string" ? payload.client_id : null;
  const userId = typeof payload.sub === "string" ? payload.sub : null;
  const scope = typeof payload.scope === "string" ? payload.scope : null;
  const expiresAt = typeof payload.exp === "number" ? payload.exp : null;

  if (
    clientId === null ||
    clientId !== authenticatedClient.client.clientId ||
    userId === null ||
    scope === null ||
    expiresAt === null
  ) {
    return {
      kind: "error",
      clientId: authenticatedClient.client.clientId,
      error: "invalid_grant",
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
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId
    };
  }

  if (
    typeof mutableClaims.claims.email === "string" &&
    mutableClaims.claims.email !== user.email
  ) {
    return {
      kind: "error",
      clientId,
      error: "invalid_request",
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
      status: 400,
      tenantId: issuerContext.tenant.id,
      userId
    };
  }

  try {
    const accessToken = await issueClientAccessToken({
      client,
      extraClaims: {
        ...configuredClaims,
        ...mutableClaims.claims
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
      status: 503,
      tenantId: issuerContext.tenant.id,
      userId
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

    try {
      const tokenSet = await issueTokenSet({
        accessTokenClaimsRepository,
        client: authenticatedClient.client,
        clientAuthMethodPolicyRepository,
        issuer: issuerContext.issuer,
        refreshTokenRepository,
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
    new Date(codeRecord.expiresAt).getTime() <= now.getTime()
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
