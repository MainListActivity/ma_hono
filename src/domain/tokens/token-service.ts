import { importJWK, SignJWT } from "jose";

import type { AuthorizationCodeRepository } from "../authorization/repository";
import { verifyPkce } from "../authorization/pkce";
import type { AccessTokenClaimsRepository } from "../clients/access-token-claims-repository";
import { resolveCustomClaims } from "../clients/resolve-custom-claims";
import type { ClientRepository } from "../clients/repository";
import type { Client } from "../clients/types";
import type { SigningKeySigner } from "../keys/signer";
import type { ResolvedIssuerContext } from "../tenants/types";
import type { UserRepository } from "../users/repository";
import { sha256Base64Url } from "../../lib/hash";
import { buildAccessTokenClaims, buildIdTokenClaims } from "./claims";
import type { OidcTokenErrorResponse, OidcTokenSuccessResponse } from "../oidc/token-response";

type TokenErrorCode = OidcTokenErrorResponse["error"];

type ClientCredentials =
  | { kind: "basic"; clientId: string; clientSecret: string }
  | { kind: "post"; clientId: string; clientSecret: string | null };

export interface TokenExchangeRequest {
  authorizationHeader: string | undefined;
  code: string;
  codeVerifier: string;
  grantType: string;
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

export const exchangeAuthorizationCode = async ({
  authorizationCodeRepository,
  accessTokenClaimsRepository,
  clientRepository,
  issuerContext,
  request,
  signer,
  userRepository
}: {
  authorizationCodeRepository: AuthorizationCodeRepository;
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  request: TokenExchangeRequest;
  signer: SigningKeySigner | undefined;
  userRepository: UserRepository;
}): Promise<TokenExchangeResult> => {
  if (request.grantType !== "authorization_code") {
    return {
      kind: "error",
      clientId: request.requestedClientId,
      error: "unsupported_grant_type",
      status: 400
    };
  }

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
    const customClaimConfigs = await accessTokenClaimsRepository.listByClientIdAndTenantId(
      client.id,
      codeRecord.tenantId
    );
    let extraClaims: Record<string, unknown> = {};

    if (customClaimConfigs.length > 0) {
      const user = await userRepository.findUserById(
        codeRecord.tenantId,
        codeRecord.userId
      );

      if (user === null) {
        return {
          kind: "error",
          clientId: client.clientId,
          error: "server_error",
          status: 400
        };
      }

      extraClaims = resolveCustomClaims(customClaimConfigs, user);
    }

    const resolvedAudience = client.accessTokenAudience ?? client.clientId;
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const idTokenClaims = buildIdTokenClaims({
      audience: client.clientId,
      issuer: issuerContext.issuer,
      nonce: codeRecord.nonce,
      nowSeconds,
      scope: codeRecord.scope,
      userId: codeRecord.userId
    });
    const accessTokenClaims = buildAccessTokenClaims({
      audience: resolvedAudience,
      clientId: client.clientId,
      extraClaims,
      issuer: issuerContext.issuer,
      nowSeconds,
      scope: codeRecord.scope,
      userId: codeRecord.userId
    });
    const [idToken, accessToken] = await Promise.all([
      createSignedJwt({
        claims: idTokenClaims,
        signer,
        tenantId: codeRecord.tenantId
      }),
      createSignedJwt({
        claims: accessTokenClaims,
        signer,
        tenantId: codeRecord.tenantId
      })
    ]);

    return {
      kind: "success",
      clientId: client.clientId,
      tenantId: codeRecord.tenantId,
      userId: codeRecord.userId,
      response: {
        token_type: "Bearer",
        expires_in: 60 * 60,
        access_token: accessToken,
        id_token: idToken,
        scope: codeRecord.scope
      }
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
