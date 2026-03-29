import { importJWK, SignJWT } from "jose";

import type { AuthorizationCodeRepository } from "../authorization/repository";
import { verifyPkce } from "../authorization/pkce";
import type { AccessTokenClaimsRepository } from "../clients/access-token-claims-repository";
import { resolveCustomClaims } from "../clients/resolve-custom-claims";
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
import { sha256Base64Url } from "../../lib/hash";
import { buildAccessTokenClaims, buildIdTokenClaims } from "./claims";
import type { OidcTokenErrorResponse, OidcTokenSuccessResponse } from "../oidc/token-response";
import type {
  RefreshTokenRecord,
  RefreshTokenRepository
} from "./refresh-token-repository";

type TokenErrorCode = OidcTokenErrorResponse["error"];

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
  requestedClientId,
  requestedClientSecret
}: {
  authorizationHeader: string | undefined;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
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
  userRepository
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
}): Promise<OidcTokenSuccessResponse | null> => {
  const customClaimConfigs = await accessTokenClaimsRepository.listByClientIdAndTenantId(
    client.id,
    tenantId
  );
  let extraClaims: Record<string, unknown> = {};

  if (customClaimConfigs.length > 0) {
    const user = await userRepository.findUserById(tenantId, userId);

    if (user === null) {
      return null;
    }

    extraClaims = resolveCustomClaims(customClaimConfigs, user);
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

export const exchangeAuthorizationCode = async ({
  authorizationCodeRepository,
  accessTokenClaimsRepository,
  clientAuthMethodPolicyRepository,
  clientRepository,
  issuerContext,
  refreshTokenRepository,
  request,
  signer,
  userRepository
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
        userRepository
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
      userRepository
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
