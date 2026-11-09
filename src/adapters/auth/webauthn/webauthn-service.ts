import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type { AuthenticationLoginChallengeRepository } from "../../../domain/authentication/login-challenge-repository";
import { isLoginChallengeActive } from "../../../domain/authentication/login-challenge";
import type {
  PasskeyCredential,
  PasskeyRepository
} from "../../../domain/authentication/passkey-repository";
import type { LoginChallenge } from "../../../domain/authorization/types";
import { isUserExpired } from "../../../domain/users/expired-user-purge";
import type { UserRepository } from "../../../domain/users/repository";
import type { User } from "../../../domain/users/types";
import { sha256Base64Url } from "../../../lib/hash";

/**
 * The relying party as the browser sees it. The RP ID and origin must match the host that
 * serves the login page, otherwise the browser refuses the ceremony.
 */
export interface PasskeyRelyingParty {
  /** WebAuthn RP ID, e.g. "auth.example.com". */
  id: string;
  /** Expected clientDataJSON origin, e.g. "https://auth.example.com". */
  origin: string;
  /** Display name shown by the authenticator during registration. */
  name: string;
}

export const passkeyCeremonyLifetimeMs = 5 * 60 * 1000;

export type PasskeyEnrollStartResult =
  | {
      kind: "challenge_issued";
      ceremonyId: string;
      options: PublicKeyCredentialCreationOptionsJSON;
    }
  | {
      kind: "rejected";
      reason: "passkey_disabled" | "user_not_found";
    };

export type PasskeyEnrollFinishResult =
  | {
      kind: "enrolled";
      credentialId: string;
    }
  | {
      kind: "rejected";
      reason: "invalid_ceremony" | "verification_failed" | "duplicate_credential";
    };

export type PasskeyLoginStartResult =
  | {
      kind: "challenge_issued";
      ceremonyId: string;
      options: PublicKeyCredentialRequestOptionsJSON;
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
      passkeyId: string;
    }
  | {
      kind: "rejected";
      reason: "invalid_ceremony" | "invalid_credentials";
    };

export interface PasskeyAssertionResult {
  newCounter: number;
  backedUp: boolean;
}

const ceremonyExpiresAt = (now: Date) =>
  new Date(now.getTime() + passkeyCeremonyLifetimeMs).toISOString();

const isPasskeyDisabledForTenant = async (
  userRepository: UserRepository,
  tenantId: string
): Promise<boolean> => {
  const policy = await userRepository.findAuthMethodPolicyByTenantId(tenantId);
  return policy !== null && !policy.passkey.enabled;
};

// agent 账号是机器身份：不登记 passkey，也永不作为人登录。
const isActiveHumanUser = (user: User | null, now: Date): user is User =>
  user !== null &&
  user.status === "active" &&
  user.kind !== "agent" &&
  !isUserExpired(user, now);

const toTransports = (
  transports: string[] | null
): AuthenticatorTransportFuture[] | undefined =>
  transports === null ? undefined : (transports as AuthenticatorTransportFuture[]);

/** Starts a registration for an already authenticated human user. */
export const startPasskeyEnrollment = async ({
  now = new Date(),
  passkeyRepository,
  relyingParty,
  tenantId,
  userId,
  userRepository
}: {
  now?: Date;
  passkeyRepository: PasskeyRepository;
  relyingParty: PasskeyRelyingParty;
  tenantId: string;
  userId: string;
  userRepository: UserRepository;
}): Promise<PasskeyEnrollStartResult> => {
  if (await isPasskeyDisabledForTenant(userRepository, tenantId)) {
    return { kind: "rejected", reason: "passkey_disabled" };
  }

  const user = await userRepository.findUserById(tenantId, userId);

  if (!isActiveHumanUser(user, now)) {
    return { kind: "rejected", reason: "user_not_found" };
  }

  const existingCredentials = await passkeyRepository.listCredentialsByUserId(tenantId, user.id);

  const options = await generateRegistrationOptions({
    rpName: relyingParty.name,
    rpID: relyingParty.id,
    userName: user.username ?? user.email,
    userDisplayName: user.displayName,
    userID: new TextEncoder().encode(user.id),
    attestationType: "none",
    excludeCredentials: existingCredentials.map((credential) => ({
      id: credential.credentialId,
      transports: toTransports(credential.transports)
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred"
    }
  });

  const ceremonyId = crypto.randomUUID();

  await passkeyRepository.createCeremony({
    id: ceremonyId,
    tenantId,
    kind: "registration",
    challenge: options.challenge,
    userId: user.id,
    loginChallengeId: null,
    expiresAt: ceremonyExpiresAt(now),
    consumedAt: null,
    createdAt: now.toISOString()
  });

  return { kind: "challenge_issued", ceremonyId, options };
};

/** Verifies a registration response against the one-time ceremony bound to the session user. */
export const finishPasskeyEnrollment = async ({
  ceremonyId,
  now = new Date(),
  passkeyRepository,
  relyingParty,
  response,
  tenantId,
  userId
}: {
  ceremonyId: string;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  relyingParty: PasskeyRelyingParty;
  response: RegistrationResponseJSON;
  tenantId: string;
  userId: string;
}): Promise<PasskeyEnrollFinishResult> => {
  const ceremony = await passkeyRepository.consumeCeremony(
    ceremonyId,
    "registration",
    now.toISOString()
  );

  if (ceremony === null || ceremony.tenantId !== tenantId || ceremony.userId !== userId) {
    return { kind: "rejected", reason: "invalid_ceremony" };
  }

  let registration: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    registration = await verifyRegistrationResponse({
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: relyingParty.origin,
      expectedRPID: relyingParty.id,
      requireUserVerification: false
    });
  } catch {
    return { kind: "rejected", reason: "verification_failed" };
  }

  if (!registration.verified || registration.registrationInfo === undefined) {
    return { kind: "rejected", reason: "verification_failed" };
  }

  const { credential, credentialBackedUp, credentialDeviceType } = registration.registrationInfo;

  const existing = await passkeyRepository.findCredentialByCredentialId(tenantId, credential.id);

  if (existing !== null) {
    return { kind: "rejected", reason: "duplicate_credential" };
  }

  const timestamp = now.toISOString();

  await passkeyRepository.createCredential({
    id: crypto.randomUUID(),
    tenantId,
    userId,
    credentialId: credential.id,
    publicKey: isoBase64URL.fromBuffer(credential.publicKey),
    signCount: credential.counter,
    transports: credential.transports ?? null,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    createdAt: timestamp,
    updatedAt: timestamp
  });

  return { kind: "enrolled", credentialId: credential.id };
};

/**
 * Starts a discoverable (usernameless) passkey login for an active login challenge.
 * The ceremony is bound to that login challenge.
 */
export const startPasskeyLogin = async ({
  issuer,
  loginChallengeRepository,
  loginChallengeToken,
  now = new Date(),
  passkeyRepository,
  relyingParty,
  tenantId,
  userRepository
}: {
  issuer: string;
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  loginChallengeToken: string;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  relyingParty: PasskeyRelyingParty;
  tenantId: string;
  userRepository: UserRepository;
}): Promise<PasskeyLoginStartResult> => {
  if (await isPasskeyDisabledForTenant(userRepository, tenantId)) {
    return { kind: "rejected", reason: "passkey_disabled" };
  }

  const loginChallengeTokenHash = await sha256Base64Url(loginChallengeToken.trim());
  const loginChallenge = await loginChallengeRepository.findByTokenHash(loginChallengeTokenHash);

  if (
    loginChallenge === null ||
    loginChallenge.issuer !== issuer ||
    loginChallenge.tenantId !== tenantId ||
    !isLoginChallengeActive(loginChallenge, now)
  ) {
    return { kind: "rejected", reason: "invalid_login_challenge" };
  }

  const options = await generateAuthenticationOptions({
    rpID: relyingParty.id,
    userVerification: "required"
  });

  const ceremonyId = crypto.randomUUID();

  await passkeyRepository.createCeremony({
    id: ceremonyId,
    tenantId,
    kind: "authentication",
    challenge: options.challenge,
    userId: null,
    loginChallengeId: loginChallenge.id,
    expiresAt: ceremonyExpiresAt(now),
    consumedAt: null,
    createdAt: now.toISOString()
  });

  return { kind: "challenge_issued", ceremonyId, options };
};

/**
 * Verifies a discoverable passkey assertion. Only a verified assertion for the ceremony's
 * login challenge authenticates the user, and only then is the signature counter advanced.
 */
export const finishPasskeyLogin = async ({
  ceremonyId,
  loginChallengeRepository,
  loginChallengeToken,
  now = new Date(),
  passkeyRepository,
  relyingParty,
  response,
  tenantId,
  userRepository
}: {
  ceremonyId: string;
  loginChallengeRepository: AuthenticationLoginChallengeRepository;
  loginChallengeToken: string;
  now?: Date;
  passkeyRepository: PasskeyRepository;
  relyingParty: PasskeyRelyingParty;
  response: AuthenticationResponseJSON;
  tenantId: string;
  userRepository: UserRepository;
}): Promise<PasskeyLoginFinishResult> => {
  const ceremony = await passkeyRepository.consumeCeremony(
    ceremonyId,
    "authentication",
    now.toISOString()
  );

  if (ceremony === null || ceremony.tenantId !== tenantId || ceremony.loginChallengeId === null) {
    return { kind: "rejected", reason: "invalid_ceremony" };
  }

  const loginChallenge = await loginChallengeRepository.findByTokenHash(
    await sha256Base64Url(loginChallengeToken.trim())
  );

  if (
    loginChallenge === null ||
    loginChallenge.id !== ceremony.loginChallengeId ||
    loginChallenge.tenantId !== tenantId ||
    !isLoginChallengeActive(loginChallenge, now)
  ) {
    return { kind: "rejected", reason: "invalid_ceremony" };
  }

  const credential = await passkeyRepository.findCredentialByCredentialId(tenantId, response.id);

  if (credential === null) {
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  const assertion = await verifyPasskeyAssertion({
    credential,
    expectedChallenge: ceremony.challenge,
    relyingParty,
    response
  });

  if (assertion === null) {
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  await passkeyRepository.updateCredentialAfterAssertion(credential.id, {
    signCount: assertion.newCounter,
    backedUp: assertion.backedUp,
    updatedAt: now.toISOString()
  });

  const user = await userRepository.findUserById(tenantId, credential.userId);

  if (!isActiveHumanUser(user, now)) {
    return { kind: "rejected", reason: "invalid_credentials" };
  }

  return {
    kind: "authenticated",
    user,
    challenge: loginChallenge,
    passkeyId: credential.id
  };
};

/**
 * Builds assertion options restricted to the given user's credentials. Used for the MFA
 * passkey step-up, where the first factor has already identified the user.
 */
export const createPasskeyStepUpOptions = async ({
  credentials,
  relyingParty
}: {
  credentials: PasskeyCredential[];
  relyingParty: PasskeyRelyingParty;
}): Promise<PublicKeyCredentialRequestOptionsJSON> =>
  generateAuthenticationOptions({
    rpID: relyingParty.id,
    allowCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: toTransports(credential.transports)
    })),
    userVerification: "required"
  });

/**
 * Verifies an assertion against a stored credential. Returns null when verification fails for
 * any reason (bad signature, wrong challenge, origin or RP ID mismatch, counter regression).
 */
export const verifyPasskeyAssertion = async ({
  credential,
  expectedChallenge,
  relyingParty,
  response
}: {
  credential: PasskeyCredential;
  expectedChallenge: string;
  relyingParty: PasskeyRelyingParty;
  response: AuthenticationResponseJSON;
}): Promise<PasskeyAssertionResult | null> => {
  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: relyingParty.origin,
      expectedRPID: relyingParty.id,
      credential: {
        id: credential.credentialId,
        publicKey: isoBase64URL.toBuffer(credential.publicKey),
        counter: credential.signCount,
        transports: toTransports(credential.transports)
      },
      requireUserVerification: true
    });

    if (!verification.verified) {
      return null;
    }

    return {
      newCounter: verification.authenticationInfo.newCounter,
      backedUp: verification.authenticationInfo.credentialBackedUp
    };
  } catch {
    return null;
  }
};
