import { importJWK, SignJWT } from "jose";

import type { AuthorizationCodeRepository } from "../authorization/repository";
import { verifyPkce } from "../authorization/pkce";
import type { ClientRepository } from "../clients/repository";
import type { SigningKeySigner } from "../keys/signer";
import type { ResolvedIssuerContext } from "../tenants/types";
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

  if (!authorizationHeader.startsWith("Basic ")) {
    return "invalid";
  }

  const encoded = authorizationHeader.slice("Basic ".length).trim();

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
  | { ok: true; clientId: string; tenantId: string }
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
      clientId: client.clientId,
      tenantId: client.tenantId
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
    clientId: client.clientId,
    tenantId: client.tenantId
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
  clientRepository,
  issuerContext,
  request,
  signer
}: {
  authorizationCodeRepository: AuthorizationCodeRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  request: TokenExchangeRequest;
  signer: SigningKeySigner | undefined;
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
      clientId: authenticatedClient.clientId,
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
      clientId: authenticatedClient.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  if (
    codeRecord.clientId !== authenticatedClient.clientId ||
    codeRecord.tenantId !== authenticatedClient.tenantId ||
    codeRecord.issuer !== issuerContext.issuer ||
    codeRecord.redirectUri !== request.redirectUri ||
    new Date(codeRecord.expiresAt).getTime() <= now.getTime()
  ) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
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
      clientId: authenticatedClient.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  const consumed = await authorizationCodeRepository.consumeById(codeRecord.id, now.toISOString());

  if (!consumed) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
      error: "invalid_grant",
      status: 400
    };
  }

  if (signer === undefined) {
    return {
      kind: "error",
      clientId: authenticatedClient.clientId,
      error: "server_error",
      status: 400
    };
  }

  try {
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const idTokenClaims = buildIdTokenClaims({
      audience: authenticatedClient.clientId,
      issuer: issuerContext.issuer,
      nonce: codeRecord.nonce,
      nowSeconds,
      scope: codeRecord.scope,
      userId: codeRecord.userId
    });
    const accessTokenClaims = buildAccessTokenClaims({
      audience: authenticatedClient.clientId,
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
      clientId: authenticatedClient.clientId,
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
      clientId: authenticatedClient.clientId,
      error: "server_error",
      status: 400
    };
  }
};
