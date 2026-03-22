export interface PasskeyCredential {
  id: string;
  tenantId: string;
  userId: string;
  credentialId: string;
  publicKeyCbor: string;
  signCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface PasskeyEnrollmentSession {
  id: string;
  tenantId: string;
  userId: string;
  challenge: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface PasskeyAssertionSession {
  id: string;
  tenantId: string;
  loginChallengeTokenHash: string;
  challenge: string;
  expiresAt: string;
  consumedAt: string | null;
  createdAt: string;
}

export interface PasskeyRepository {
  createEnrollmentSession(session: PasskeyEnrollmentSession): Promise<void>;
  findEnrollmentSessionById(id: string): Promise<PasskeyEnrollmentSession | null>;
  consumeEnrollmentSession(id: string, consumedAt: string): Promise<boolean>;
  createCredential(credential: PasskeyCredential): Promise<void>;
  findCredentialByCredentialId(tenantId: string, credentialId: string): Promise<PasskeyCredential | null>;
  updateCredentialSignCount(id: string, signCount: number): Promise<void>;
  listCredentialsByUserId(tenantId: string, userId: string): Promise<PasskeyCredential[]>;
  createAssertionSession(session: PasskeyAssertionSession): Promise<void>;
  findAssertionSessionById(id: string): Promise<PasskeyAssertionSession | null>;
  consumeAssertionSession(id: string, consumedAt: string): Promise<boolean>;
}
