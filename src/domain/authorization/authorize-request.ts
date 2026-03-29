import type { ClientRepository } from "../clients/repository";
import type { ResolvedIssuerContext } from "../tenants/types";
import { sha256Base64Url } from "../../lib/hash";
import type { AuthorizationCodeRepository, LoginChallengeRepository } from "./repository";
import { validatePkceParameters } from "./pkce";
import type {
  AuthorizationCode,
  AuthorizeRequestParameters,
  AuthorizeRequestResult,
  AuthorizeSession,
  LoginChallenge,
  ValidatedAuthorizeRequest
} from "./types";

const REGEX_PREFIX = "regex:";

const matchRedirectUri = (registeredUris: string[], redirectUri: string): boolean =>
  registeredUris.some((entry) => {
    if (entry.startsWith(REGEX_PREFIX)) {
      try {
        return new RegExp(`^${entry.slice(REGEX_PREFIX.length)}$`).test(redirectUri);
      } catch {
        return false;
      }
    }
    return entry === redirectUri;
  });

const authorizationCodeLifetimeMs = 5 * 60 * 1000;
const loginChallengeLifetimeMs = 10 * 60 * 1000;

const createOpaqueToken = () => crypto.randomUUID().replaceAll("-", "");

const canAutoApproveAuthorization = (request: ValidatedAuthorizeRequest) =>
  request.client.trustLevel === "first_party_trusted" &&
  request.client.consentPolicy === "skip";

const includesOpenIdScope = (scope: string) =>
  scope
    .split(/\s+/u)
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .includes("openid");

const buildValidatedAuthorizeRequest = async ({
  clientRepository,
  issuerContext,
  request
}: {
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  request: AuthorizeRequestParameters;
}): Promise<ValidatedAuthorizeRequest | AuthorizeRequestResult> => {
  const clientId = request.clientId.trim();
  const redirectUri = request.redirectUri.trim();

  if (clientId.length === 0) {
    return {
      kind: "error",
      error: "invalid_client",
      clientId: null,
      redirectUri: redirectUri.length > 0 ? redirectUri : null,
      state: request.state,
      shouldRedirect: false
    };
  }

  const client = await clientRepository.findByClientId(clientId);

  if (client === null || client.tenantId !== issuerContext.tenant.id) {
    return {
      kind: "error",
      error: "invalid_client",
      clientId,
      redirectUri: redirectUri.length > 0 ? redirectUri : null,
      state: request.state,
      shouldRedirect: false
    };
  }

  if (!matchRedirectUri(client.redirectUris, redirectUri)) {
    return {
      kind: "error",
      error: "invalid_redirect_uri",
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: false
    };
  }

  if (!client.grantTypes.includes("authorization_code")) {
    return {
      kind: "error",
      error: "unauthorized_client",
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: true
    };
  }

  if (!client.responseTypes.includes("code")) {
    return {
      kind: "error",
      error: "unauthorized_client",
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: true
    };
  }

  if (request.responseType !== "code") {
    return {
      kind: "error",
      error: "unsupported_response_type",
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: true
    };
  }

  if (!includesOpenIdScope(request.scope)) {
    return {
      kind: "error",
      error: "invalid_scope",
      errorDescription: "scope must include openid",
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: true
    };
  }

  const pkce = validatePkceParameters({
    codeChallenge: request.codeChallenge,
    codeChallengeMethod: request.codeChallengeMethod
  });

  if (!pkce.ok) {
    return {
      kind: "error",
      error: "invalid_request",
      errorDescription: pkce.errorDescription,
      clientId,
      redirectUri,
      state: request.state,
      shouldRedirect: true
    };
  }

  return {
    client,
    clientId,
    issuer: issuerContext.issuer,
    redirectUri,
    scope: request.scope.trim(),
    state: request.state,
    nonce: request.nonce,
    tenantId: issuerContext.tenant.id,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: pkce.codeChallengeMethod
  };
};

export const authorizeRequest = async ({
  authMethod = null,
  authorizationCodeRepository,
  clientRepository,
  issuerContext,
  loginChallengeRepository,
  now = new Date(),
  request,
  session
}: {
  authMethod?: AuthorizationCode["authMethod"];
  authorizationCodeRepository: AuthorizationCodeRepository;
  clientRepository: ClientRepository;
  issuerContext: ResolvedIssuerContext;
  loginChallengeRepository: LoginChallengeRepository;
  now?: Date;
  request: AuthorizeRequestParameters;
  session: AuthorizeSession | null;
}): Promise<AuthorizeRequestResult> => {
  const validatedRequest = await buildValidatedAuthorizeRequest({
    clientRepository,
    issuerContext,
    request
  });

  if ("kind" in validatedRequest) {
    return validatedRequest;
  }

  if (session === null) {
    const loginChallengeToken = createOpaqueToken();
    const loginChallenge: LoginChallenge = {
      id: crypto.randomUUID(),
      tenantId: validatedRequest.tenantId,
      issuer: validatedRequest.issuer,
      clientId: validatedRequest.clientId,
      authMethod: null,
      redirectUri: validatedRequest.redirectUri,
      scope: validatedRequest.scope,
      state: validatedRequest.state ?? "",
      codeChallenge: validatedRequest.codeChallenge,
      codeChallengeMethod: validatedRequest.codeChallengeMethod,
      nonce: validatedRequest.nonce,
      tokenHash: await sha256Base64Url(loginChallengeToken),
      expiresAt: new Date(now.getTime() + loginChallengeLifetimeMs).toISOString(),
      consumedAt: null,
      authenticatedUserId: null,
      mfaState: "none" as const,
      mfaAttemptCount: 0,
      enrollmentAttemptCount: 0,
      totpEnrollmentSecretEncrypted: null,
      createdAt: now.toISOString()
    };

    await loginChallengeRepository.create(loginChallenge);

    return {
      kind: "login_required",
      loginChallenge,
      loginChallengeToken
    };
  }

  if (!canAutoApproveAuthorization(validatedRequest)) {
    return {
      kind: "consent_required",
      request: validatedRequest
    };
  }

  const code = createOpaqueToken();
  const authorizationCode: AuthorizationCode = {
    id: crypto.randomUUID(),
    tenantId: validatedRequest.tenantId,
    issuer: validatedRequest.issuer,
    clientId: validatedRequest.clientId,
    authMethod,
    userId: session.userId,
    redirectUri: validatedRequest.redirectUri,
    scope: validatedRequest.scope,
    nonce: validatedRequest.nonce,
    codeChallenge: validatedRequest.codeChallenge,
    codeChallengeMethod: validatedRequest.codeChallengeMethod,
    tokenHash: await sha256Base64Url(code),
    expiresAt: new Date(now.getTime() + authorizationCodeLifetimeMs).toISOString(),
    consumedAt: null,
    createdAt: now.toISOString()
  };

  await authorizationCodeRepository.create(authorizationCode);

  return {
    kind: "authorization_granted",
    authorizationCode,
    code,
    request: validatedRequest,
    session
  };
};
