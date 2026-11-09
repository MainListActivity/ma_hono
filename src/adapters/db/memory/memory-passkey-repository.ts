import type {
  PasskeyCeremony,
  PasskeyCeremonyKind,
  PasskeyCredential,
  PasskeyRepository
} from "../../../domain/authentication/passkey-repository";

export class MemoryPasskeyRepository implements PasskeyRepository {
  private readonly credentials: PasskeyCredential[] = [];
  private readonly ceremonies: PasskeyCeremony[] = [];

  async createCeremony(ceremony: PasskeyCeremony): Promise<void> {
    this.ceremonies.push({ ...ceremony });
  }

  async consumeCeremony(
    id: string,
    kind: PasskeyCeremonyKind,
    now: string
  ): Promise<PasskeyCeremony | null> {
    const ceremony = this.ceremonies.find((c) => c.id === id);

    if (
      ceremony === undefined ||
      ceremony.kind !== kind ||
      ceremony.consumedAt !== null ||
      new Date(ceremony.expiresAt).getTime() <= new Date(now).getTime()
    ) {
      return null;
    }

    ceremony.consumedAt = now;
    return { ...ceremony };
  }

  async createCredential(credential: PasskeyCredential): Promise<void> {
    this.credentials.push({ ...credential });
  }

  async findCredentialByCredentialId(
    tenantId: string,
    credentialId: string
  ): Promise<PasskeyCredential | null> {
    const credential = this.credentials.find(
      (c) => c.tenantId === tenantId && c.credentialId === credentialId
    );
    return credential === undefined ? null : { ...credential };
  }

  async listCredentialsByUserId(tenantId: string, userId: string): Promise<PasskeyCredential[]> {
    return this.credentials
      .filter((c) => c.tenantId === tenantId && c.userId === userId)
      .map((c) => ({ ...c }));
  }

  async updateCredentialAfterAssertion(
    id: string,
    update: { signCount: number; backedUp: boolean; updatedAt: string }
  ): Promise<void> {
    const credential = this.credentials.find((c) => c.id === id);

    if (credential !== undefined) {
      credential.signCount = update.signCount;
      credential.backedUp = update.backedUp;
      credential.updatedAt = update.updatedAt;
    }
  }

  listCredentials(): PasskeyCredential[] {
    return this.credentials.map((c) => ({ ...c }));
  }
}
