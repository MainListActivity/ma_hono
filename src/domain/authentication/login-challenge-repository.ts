import type { LoginChallenge } from "../authorization/types";

export interface AuthenticationLoginChallengeRepository {
  consume(challengeId: string, consumedAt: string): Promise<boolean>;
  findByTokenHash(tokenHash: string): Promise<LoginChallenge | null>;
  /** Set authenticated_user_id and mfa_state after first-factor success */
  setMfaState(
    challengeId: string,
    authenticatedUserId: string,
    mfaState: LoginChallenge["mfaState"]
  ): Promise<void>;
  /** Increment mfa_attempt_count. Returns new count. */
  incrementMfaAttemptCount(challengeId: string): Promise<number>;
  /** Increment enrollment_attempt_count. Returns new count. */
  incrementEnrollmentAttemptCount(challengeId: string): Promise<number>;
  /** Update mfa_state to 'satisfied' */
  satisfyMfa(challengeId: string): Promise<void>;
  /** Store encrypted enrollment secret */
  setTotpEnrollmentSecret(challengeId: string, secretEncrypted: string): Promise<void>;
  /** Clear enrollment secret and set mfa_state = satisfied */
  completeEnrollment(challengeId: string): Promise<void>;
}
