import type {
  ActivateUserByInvitationTokenInput,
  ActivateUserByInvitationTokenResult,
  CreateProvisionedUserWithInvitationInput,
  UserRepository
} from "../../../domain/users/repository";
import type {
  PasswordCredential,
  TenantAuthMethodPolicy,
  User,
  UserInvitation
} from "../../../domain/users/types";

export class MemoryUserRepository implements UserRepository {
  private readonly invitations: UserInvitation[];
  private readonly passwordCredentials: PasswordCredential[];
  private readonly policies: TenantAuthMethodPolicy[];
  private readonly users: User[];

  constructor({
    failActivationCommit = false,
    failProvisionCommit = false,
    invitations = [],
    passwordCredentials = [],
    policies = [],
    users = []
  }: {
    failActivationCommit?: boolean;
    failProvisionCommit?: boolean;
    invitations?: UserInvitation[];
    passwordCredentials?: PasswordCredential[];
    policies?: TenantAuthMethodPolicy[];
    users?: User[];
  } = {}) {
    this.failActivationCommit = failActivationCommit;
    this.failProvisionCommit = failProvisionCommit;
    this.invitations = [...invitations];
    this.passwordCredentials = [...passwordCredentials];
    this.policies = [...policies];
    this.users = [...users];
  }

  private readonly failActivationCommit: boolean;
  private readonly failProvisionCommit: boolean;

  async activateUserByInvitationToken({
    createPasswordHash,
    now,
    tokenHash
  }: ActivateUserByInvitationTokenInput): Promise<ActivateUserByInvitationTokenResult> {
    const index = this.invitations.findIndex((invitation) => invitation.tokenHash === tokenHash);

    if (index === -1) {
      return {
        kind: "not_found"
      };
    }

    const invitation = this.invitations[index];

    if (invitation === undefined) {
      return {
        kind: "not_found"
      };
    }

    if (invitation.consumedAt !== null) {
      return {
        kind: "already_used"
      };
    }

    if (new Date(invitation.expiresAt).getTime() <= now.getTime()) {
      return {
        kind: "expired"
      };
    }

    const userIndex = this.users.findIndex(
      (user) => user.tenantId === invitation.tenantId && user.id === invitation.userId
    );
    const user = this.users[userIndex];

    if (user === undefined) {
      return {
        kind: "not_found"
      };
    }

    if (user.status === "disabled") {
      return {
        kind: "user_disabled"
      };
    }

    const existingCredentialIndex = this.passwordCredentials.findIndex(
      (credential) =>
        credential.tenantId === invitation.tenantId && credential.userId === invitation.userId
    );

    if (user.status !== "provisioned" || existingCredentialIndex !== -1) {
      return {
        kind: "already_initialized"
      };
    }

    if (this.failActivationCommit) {
      throw new Error("simulated activation commit failure");
    }

    const updatedAt = now.toISOString();
    const passwordHash = await createPasswordHash();
    const consumedInvitation: UserInvitation = {
      ...invitation,
      consumedAt: updatedAt
    };
    const activatedUser: User = {
      ...user,
      emailVerified: true,
      status: "active",
      updatedAt
    };
    const credential: PasswordCredential = {
      id: crypto.randomUUID(),
      tenantId: user.tenantId,
      userId: user.id,
      passwordHash,
      createdAt: updatedAt,
      updatedAt
    };

    this.invitations[index] = consumedInvitation;
    this.users[userIndex] = activatedUser;
    this.passwordCredentials.push(credential);

    return {
      kind: "activated",
      credential,
      invitation: consumedInvitation,
      user: activatedUser
    };
  }

  async createProvisionedUserWithInvitation({
    invitation,
    user
  }: CreateProvisionedUserWithInvitationInput): Promise<void> {
    if (this.users.some((storedUser) => storedUser.tenantId === user.tenantId && storedUser.email === user.email)) {
      throw new Error(`user email already exists for tenant: ${user.tenantId}`);
    }

    if (
      user.username !== null &&
      this.users.some(
        (storedUser) => storedUser.tenantId === user.tenantId && storedUser.username === user.username
      )
    ) {
      throw new Error(`username already exists for tenant: ${user.tenantId}`);
    }

    if (this.failProvisionCommit) {
      throw new Error("simulated provision commit failure");
    }

    this.users.push(user);
    this.invitations.push(invitation);
  }

  async findAuthMethodPolicyByTenantId(tenantId: string): Promise<TenantAuthMethodPolicy | null> {
    return this.policies.find((policy) => policy.tenantId === tenantId) ?? null;
  }

  async findPasswordCredentialByUserId(
    tenantId: string,
    userId: string
  ): Promise<PasswordCredential | null> {
    return (
      this.passwordCredentials.find(
        (credential) => credential.tenantId === tenantId && credential.userId === userId
      ) ?? null
    );
  }

  async findUserByEmail(tenantId: string, email: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.email === email) ?? null;
  }

  async findUserById(tenantId: string, userId: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.id === userId) ?? null;
  }

  async findUserByUsername(tenantId: string, username: string): Promise<User | null> {
    return this.users.find((user) => user.tenantId === tenantId && user.username === username) ?? null;
  }

  async listByTenantId(tenantId: string): Promise<User[]> {
    return this.users.filter((user) => user.tenantId === tenantId);
  }

  listInvitations(): UserInvitation[] {
    return [...this.invitations];
  }

  listUsers(): User[] {
    return [...this.users];
  }

  async updateUser(user: User): Promise<void> {
    const index = this.users.findIndex(
      (storedUser) => storedUser.tenantId === user.tenantId && storedUser.id === user.id
    );

    if (index === -1) {
      throw new Error(`user not found: ${user.id}`);
    }

    this.users[index] = user;
  }

  async upsertPasswordCredential(credential: PasswordCredential): Promise<void> {
    const index = this.passwordCredentials.findIndex(
      (storedCredential) =>
        storedCredential.tenantId === credential.tenantId && storedCredential.userId === credential.userId
    );

    if (index === -1) {
      this.passwordCredentials.push(credential);
      return;
    }

    this.passwordCredentials[index] = credential;
  }
}
