import type { Client } from "../clients/types";

export type PkceCodeChallengeMethod = "S256";

export interface AuthorizeSession {
  userId: string;
}

export interface AuthorizeRequestParameters {
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope: string;
  state: string | null;
  nonce: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
}

export interface ValidatedAuthorizeRequest {
  client: Client;
  clientId: string;
  issuer: string;
  redirectUri: string;
  scope: string;
  state: string | null;
  nonce: string | null;
  tenantId: string;
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
}

export interface LoginChallenge {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  nonce: string | null;
  tokenHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface AuthorizationCode {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  tokenHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export type AuthorizeFailureError =
  | "invalid_client"
  | "invalid_redirect_uri"
  | "invalid_request"
  | "unsupported_response_type";

export interface AuthorizeFailureResult {
  kind: "error";
  error: AuthorizeFailureError;
  errorDescription?: string;
  clientId: string | null;
  redirectUri: string | null;
}

export interface AuthorizeLoginRequiredResult {
  kind: "login_required";
  loginChallenge: LoginChallenge;
  loginChallengeToken: string;
}

export interface AuthorizeConsentRequiredResult {
  kind: "consent_required";
  request: ValidatedAuthorizeRequest;
}

export interface AuthorizeGrantedResult {
  kind: "authorization_granted";
  authorizationCode: AuthorizationCode;
  code: string;
  request: ValidatedAuthorizeRequest;
  session: AuthorizeSession;
}

export type AuthorizeRequestResult =
  | AuthorizeFailureResult
  | AuthorizeLoginRequiredResult
  | AuthorizeConsentRequiredResult
  | AuthorizeGrantedResult;
