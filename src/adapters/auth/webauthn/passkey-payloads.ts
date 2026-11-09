import { z } from "zod";

// Request bodies for the WebAuthn endpoints. Objects are strict so that legacy fields
// (credential_id, sign_count, public_key_cbor, *_session_id) are rejected instead of ignored.

const base64UrlString = (maxLength: number) =>
  z.string().min(1).max(maxLength).regex(/^[A-Za-z0-9_-]+$/);

const authenticatorTransportSchema = z.enum([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb"
]);

const credentialCommonSchema = {
  id: base64UrlString(1024),
  rawId: base64UrlString(1024),
  type: z.literal("public-key"),
  authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown())
};

export const registrationCredentialSchema = z.strictObject({
  ...credentialCommonSchema,
  response: z.strictObject({
    clientDataJSON: base64UrlString(4096),
    attestationObject: base64UrlString(16384),
    authenticatorData: base64UrlString(4096).optional(),
    transports: z.array(authenticatorTransportSchema).max(8).optional(),
    publicKeyAlgorithm: z.number().int().optional(),
    publicKey: base64UrlString(4096).optional()
  })
});

export const authenticationCredentialSchema = z.strictObject({
  ...credentialCommonSchema,
  response: z.strictObject({
    clientDataJSON: base64UrlString(4096),
    authenticatorData: base64UrlString(4096),
    signature: base64UrlString(4096),
    userHandle: base64UrlString(1024).nullish()
  })
});

const ceremonyIdSchema = z.string().min(1).max(64);
const loginChallengeTokenSchema = z.string().min(1).max(512);

export const passkeyEnrollFinishPayloadSchema = z.strictObject({
  ceremony_id: ceremonyIdSchema,
  credential: registrationCredentialSchema
});

export const passkeyLoginFinishPayloadSchema = z.strictObject({
  ceremony_id: ceremonyIdSchema,
  login_challenge: loginChallengeTokenSchema,
  credential: authenticationCredentialSchema
});

export const mfaPasskeyStartPayloadSchema = z.strictObject({
  login_challenge: loginChallengeTokenSchema
});

export const mfaPasskeyFinishPayloadSchema = z.strictObject({
  login_challenge: loginChallengeTokenSchema,
  challenge: base64UrlString(256),
  credential: authenticationCredentialSchema
});
