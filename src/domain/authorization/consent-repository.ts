import type { ValidatedAuthorizeRequest } from "./types";

export interface ConsentChallenge {
  id: string;
  tenantId: string;
  issuer: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  resource: string | null;
  state: string | null;
  nonce: string | null;
  codeChallenge: string;
  codeChallengeMethod: ValidatedAuthorizeRequest["codeChallengeMethod"];
  tokenHash: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface ConsentChallengeRepository {
  create(challenge: ConsentChallenge): Promise<void>;
  findActiveByTokenHash(tokenHash: string): Promise<ConsentChallenge | null>;
  consumeById(id: string, consumedAt: string): Promise<boolean>;
}

