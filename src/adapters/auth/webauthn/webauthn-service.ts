import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import type {
  PasskeyRepository
} from "../../../domain/authentication/passkey-repository";
import type { LoginChallenge } from "../../../domain/authorization/types";
import type { User } from "../../../domain/users/types";
import type { UserRepository } from "../../../domain/users/repository";
import { sha256Base64Url } from "../../../lib/hash";

export type PasskeyEnrollStartResult =
  | {
      kind: "challenge_issued";
      challenge: string;
      enrollmentSessionId: string;
    }
  | {
      kind: "rejected";
      reason: "passkey_disabled" | "user_not_found";
    };

export type PasskeyEnrollFinishResult =
  | {
      kind: "enrolled";
    }
  | {
      kind: "rejected";
      reason: "invalid_session" | "duplicate_credential";
    };

export type PasskeyLoginStartResult =
  | {
      kind: "challenge_issued";
      challenge: string;
      assertionSessionId: string;
    }
  | {
      kind: "rejected";
      reason: "passkey_disabled" | "invalid_login_challenge";
    };

export type PasskeyLoginFinishResult =
  | {
      kind: "authenticated";
      user: User;
      challenge: LoginChallenge;
    }
  | {
      kind: "rejected";
      reason: "invalid_credentials" | "invalid_session";
    };

export const startPasskeyEnrollment = async ({
  passkeyRepository,
  now = new Date(),
  tenantId,
  userId,
  userRepository
}: {
  passkeyRepository: PasskeyRepository;
  now?: Date;
  tenantId: string;
  userId: string;
  userRepository: UserRepository;
}): Promise<PasskeyEnrollStartResult> => {
  const policy = await userRepository.findAuthMethodPolicyByTenantId(tenantId);

  if (policy !== null && !policy.passkey.enabled) {
    return { kind: "rejected", reason: "passkey_disabled" };
  }

  const user = await userRepository.findUserById(tenantId, userId);

  if (user === null || user.status !== "active") {
    return { kind: "rejected", reason: "user_not_found" };
  }

  const challenge = crypto.randomUUID();
  const enrollmentSessionId = crypto.randomUUID();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();

  await passkeyRepository.createEnrollmentSession({
    id: enrollmentSessionId,
    tenantId,
    userId,
    challenge,
    expiresAt,
    consumedAt: null,
    createdAt: now.toISOString()
  });

  return { kind: "challenge_issued", challenge, enrollmentSessionId };
};

export const finishPasskeyEnrollment = async ({
  credentialId,
  enrollmentSessionId,
  now = new Date(),
  passkeyRepository,
  publicKeyCbor,
  signCount
}: {
  credentialId: string;
  enrollmentSessionId: string;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  publicKeyCbor: string;
  signCount: number;
}): Promise<PasskeyEnrollFinishResult> => {
  const session = await passkeyRepository.findEnrollmentSessionById(enrollmentSessionId);

  if (session === null || new Date(session.expiresAt).getTime() <= now.getTime()) {
    return { kind: "rejected", reason: "invalid_session" };
  }

  const consumed = await passkeyRepository.consumeEnrollmentSession(
    session.id,
    now.toISOString()
  );

  if (!consumed) {
    return { kind: "rejected", reason: "invalid_session" };
  }

  const existing = await passkeyRepository.findCredentialByCredentialId(
    session.tenantId,
    credentialId
  );

  if (existing !== null) {
    return { kind: "rejected", reason: "duplicate_credential" };
  }

  await passkeyRepository.createCredential({
    id: crypto.randomUUID(),
    tenantId: session.tenantId,
    userId: session.userId,
    credentialId,
    publicKeyCbor,
    signCount,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString()
  });

  return { kind: "enrolled" };
};

export const startPasskeyLogin = async ({
  issuer,
  loginChallengeRepository,
  loginChallengeToken,
  now = new Date(),
  passkeyRepository,
  tenantId,
  userRepository
}: {
  issuer: string;
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  loginChallengeToken: string;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  tenantId: string;
  userRepository: UserRepository;
}): Promise<PasskeyLoginStartResult> => {
  const policy = await userRepository.findAuthMethodPolicyByTenantId(tenantId);

  if (policy !== null && !policy.passkey.enabled) {
    return { kind: "rejected", reason: "passkey_disabled" };
  }

  const normalizedToken = loginChallengeToken.trim();
  const loginChallengeTokenHash = await sha256Base64Url(normalizedToken);
  const loginChallenge = await loginChallengeRepository.findByTokenHash(loginChallengeTokenHash);

  if (
    loginChallenge === null ||
    loginChallenge.issuer !== issuer ||
    loginChallenge.tenantId !== tenantId ||
    new Date(loginChallenge.expiresAt).getTime() <= now.getTime()
  ) {
    return { kind: "rejected", reason: "invalid_login_challenge" };
  }

  const challenge = crypto.randomUUID();
  const assertionSessionId = crypto.randomUUID();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();

  await passkeyRepository.createAssertionSession({
    id: assertionSessionId,
    tenantId,
    loginChallengeTokenHash,
    challenge,
    expiresAt,
    consumedAt: null,
    createdAt: now.toISOString()
  });

  return { kind: "challenge_issued", challenge, assertionSessionId };
};

export const finishPasskeyLogin = async ({
  assertionSessionId,
  credentialId,
  loginChallengeRepository,
  now = new Date(),
  passkeyRepository,
  signCount,
  userRepository
}: {
  assertionSessionId: string;
  credentialId: string;
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  signCount: number;
  userRepository: UserRepository;
}): Promise<PasskeyLoginFinishResult> => {
  const assertionSession = await passkeyRepository.findAssertionSessionById(assertionSessionId);

  if (
    assertionSession === null ||
    new Date(assertionSession.expiresAt).getTime() <= now.getTime()
  ) {
    return { kind: "rejected", reason: "invalid_session" };
  }

  const credential = await passkeyRepository.findCredentialByCredentialId(
    assertionSession.tenantId,
    credentialId
  );

  if (credential === null) {
    await recordLoginFailure(assertionSession.id, passkeyRepository, now);
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  // Verify sign count is not replayed (counter must advance or stay at 0)
  if (credential.signCount > 0 && signCount <= credential.signCount) {
    await recordLoginFailure(assertionSession.id, passkeyRepository, now);
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  const loginChallenge = await loginChallengeRepository.findByTokenHash(
    assertionSession.loginChallengeTokenHash
  );

  if (loginChallenge === null) {
    await recordLoginFailure(assertionSession.id, passkeyRepository, now);
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  // Consume assertion session atomically
  const sessionConsumed = await passkeyRepository.consumeAssertionSession(
    assertionSession.id,
    now.toISOString()
  );

  if (!sessionConsumed) {
    return { kind: "rejected", reason: "invalid_session" };
  }

  // Update sign count
  await passkeyRepository.updateCredentialSignCount(credential.id, signCount);

  const user = await userRepository.findUserById(credential.tenantId, credential.userId);

  if (user === null || user.status !== "active") {
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  return { kind: "authenticated", user, challenge: loginChallenge };
};

const recordLoginFailure = async (
  assertionSessionId: string,
  passkeyRepository: PasskeyRepository,
  now: Date
): Promise<void> => {
  await passkeyRepository.consumeAssertionSession(assertionSessionId, now.toISOString());
};
