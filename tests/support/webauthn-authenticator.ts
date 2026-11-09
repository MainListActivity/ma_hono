import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON
} from "@simplewebauthn/server";

/**
 * A software ES256 authenticator for tests. It emits the same JSON shapes that
 * @simplewebauthn/browser returns, so the server runs its real WebAuthn verification.
 * Only the "none" attestation format and ES256 are implemented.
 */

type CborKey = number | string;
type CborValue = number | string | Uint8Array | Map<CborKey, CborValue>;

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
};

const encodeHead = (majorType: number, value: number): Uint8Array => {
  const major = majorType << 5;

  if (value < 24) return Uint8Array.of(major | value);
  if (value < 0x100) return Uint8Array.of(major | 24, value);
  if (value < 0x10000) return Uint8Array.of(major | 25, value >> 8, value & 0xff);

  return Uint8Array.of(
    major | 26,
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  );
};

const encodeCbor = (value: CborValue): Uint8Array => {
  if (typeof value === "number") {
    return value >= 0 ? encodeHead(0, value) : encodeHead(1, -1 - value);
  }

  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concatBytes([encodeHead(3, bytes.length), bytes]);
  }

  if (value instanceof Uint8Array) {
    return concatBytes([encodeHead(2, value.length), value]);
  }

  const entries = [...value.entries()];
  return concatBytes([
    encodeHead(5, entries.length),
    ...entries.flatMap(([key, entryValue]) => [encodeCbor(key), encodeCbor(entryValue)])
  ]);
};

const u16 = (value: number) => Uint8Array.of((value >> 8) & 0xff, value & 0xff);

const u32 = (value: number) =>
  Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);

const sha256 = (data: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(data).digest());

const toBase64Url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

const clientDataJson = (type: "webauthn.create" | "webauthn.get", challenge: string, origin: string) =>
  new TextEncoder().encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

export interface VirtualAuthenticator {
  readonly credentialId: string;
  /** base64url COSE public key, the form the server stores after registration. */
  readonly publicKey: string;
  createRegistrationResponse(options: {
    challenge: string;
    origin: string;
    rpId: string;
  }): RegistrationResponseJSON;
  createAssertionResponse(options: {
    challenge: string;
    origin: string;
    rpId: string;
    /** Overrides the authenticator's own counter, for regression tests. */
    signCount?: number;
  }): AuthenticationResponseJSON;
}

export const createVirtualAuthenticator = (): VirtualAuthenticator => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const credentialIdBytes = randomBytes(32);
  const credentialId = credentialIdBytes.toString("base64url");

  const coseKey = encodeCbor(
    new Map<CborKey, CborValue>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
      [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))]
    ])
  );

  let counter = 0;

  return {
    credentialId,
    publicKey: toBase64Url(coseKey),

    createRegistrationResponse({ challenge, origin, rpId }) {
      const attestedCredentialData = concatBytes([
        new Uint8Array(16),
        u16(credentialIdBytes.length),
        new Uint8Array(credentialIdBytes),
        coseKey
      ]);
      const authenticatorData = concatBytes([
        sha256(new TextEncoder().encode(rpId)),
        Uint8Array.of(FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL_DATA),
        u32(counter),
        attestedCredentialData
      ]);
      const attestationObject = encodeCbor(
        new Map<CborKey, CborValue>([
          ["fmt", "none"],
          ["attStmt", new Map<CborKey, CborValue>()],
          ["authData", authenticatorData]
        ])
      );

      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: toBase64Url(clientDataJson("webauthn.create", challenge, origin)),
          attestationObject: toBase64Url(attestationObject),
          transports: ["internal"]
        }
      };
    },

    createAssertionResponse({ challenge, origin, rpId, signCount }) {
      counter = signCount ?? counter + 1;

      const authenticatorData = concatBytes([
        sha256(new TextEncoder().encode(rpId)),
        Uint8Array.of(FLAG_USER_PRESENT | FLAG_USER_VERIFIED),
        u32(counter)
      ]);
      const clientData = clientDataJson("webauthn.get", challenge, origin);
      const signature = sign(
        "sha256",
        Buffer.concat([authenticatorData, sha256(clientData)]),
        { key: privateKey, dsaEncoding: "der" }
      );

      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: toBase64Url(clientData),
          authenticatorData: toBase64Url(authenticatorData),
          signature: toBase64Url(new Uint8Array(signature))
        }
      };
    }
  };
};
