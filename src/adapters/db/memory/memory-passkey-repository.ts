import type {
  PasskeyAssertionSession,
  PasskeyCredential,
  PasskeyEnrollmentSession,
  PasskeyRepository
} from "../../../domain/authentication/passkey-repository";

export class MemoryPasskeyRepository implements PasskeyRepository {
  private readonly credentials: PasskeyCredential[] = [];
  private readonly enrollmentSessions: PasskeyEnrollmentSession[] = [];
  private readonly assertionSessions: PasskeyAssertionSession[] = [];

  async createEnrollmentSession(session: PasskeyEnrollmentSession): Promise<void> {
    this.enrollmentSessions.push(session);
  }

  async findEnrollmentSessionById(id: string): Promise<PasskeyEnrollmentSession | null> {
    return this.enrollmentSessions.find((s) => s.id === id && s.consumedAt === null) ?? null;
  }

  async consumeEnrollmentSession(id: string, consumedAt: string): Promise<boolean> {
    const session = this.enrollmentSessions.find((s) => s.id === id && s.consumedAt === null);
    if (session !== undefined) {
      session.consumedAt = consumedAt;
      return true;
    }
    return false;
  }

  async createCredential(credential: PasskeyCredential): Promise<void> {
    this.credentials.push(credential);
  }

  async findCredentialByCredentialId(
    tenantId: string,
    credentialId: string
  ): Promise<PasskeyCredential | null> {
    return (
      this.credentials.find(
        (c) => c.tenantId === tenantId && c.credentialId === credentialId
      ) ?? null
    );
  }

  async updateCredentialSignCount(id: string, signCount: number): Promise<void> {
    const credential = this.credentials.find((c) => c.id === id);
    if (credential !== undefined) {
      credential.signCount = signCount;
    }
  }

  async listCredentialsByUserId(tenantId: string, userId: string): Promise<PasskeyCredential[]> {
    return this.credentials.filter(c => c.tenantId === tenantId && c.userId === userId);
  }

  async createAssertionSession(session: PasskeyAssertionSession): Promise<void> {
    this.assertionSessions.push(session);
  }

  async findAssertionSessionById(id: string): Promise<PasskeyAssertionSession | null> {
    return this.assertionSessions.find((s) => s.id === id && s.consumedAt === null) ?? null;
  }

  async consumeAssertionSession(id: string, consumedAt: string): Promise<boolean> {
    const session = this.assertionSessions.find((s) => s.id === id && s.consumedAt === null);
    if (session !== undefined) {
      session.consumedAt = consumedAt;
      return true;
    }
    return false;
  }

  listCredentials(): PasskeyCredential[] {
    return [...this.credentials];
  }
}
