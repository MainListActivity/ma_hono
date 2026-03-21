import { encodeBase64Url } from "./base64url";

const ITERATIONS = 100_000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;

const textEncoder = new TextEncoder();

const importKey = (password: string) =>
  crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

const deriveBits = (key: CryptoKey, salt: Uint8Array) =>
  crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: ITERATIONS
    },
    key,
    KEY_LENGTH * 8
  );

export const hashPasswordPbkdf2 = async (password: string): Promise<string> => {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await importKey(password);
  const derived = await deriveBits(key, salt);

  return `${ITERATIONS}:${encodeBase64Url(salt)}:${encodeBase64Url(derived)}`;
};

const decodeBase64Url = (str: string): Uint8Array => {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
};

export const verifyPasswordPbkdf2 = async (
  password: string,
  hash: string
): Promise<boolean> => {
  try {
    const parts = hash.split(":");

    if (parts.length !== 3) {
      return false;
    }

    const [iterationsStr, saltB64, expectedB64] = parts;
    const iterations = parseInt(iterationsStr, 10);

    if (!Number.isInteger(iterations) || iterations <= 0) {
      return false;
    }

    const salt = decodeBase64Url(saltB64);
    const expected = decodeBase64Url(expectedB64);
    const key = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const derived = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      key,
      expected.byteLength * 8
    );
    const derivedBytes = new Uint8Array(derived);

    if (derivedBytes.length !== expected.length) {
      return false;
    }

    // Constant-time comparison
    let diff = 0;

    for (let i = 0; i < derivedBytes.length; i++) {
      diff |= derivedBytes[i] ^ expected[i];
    }

    return diff === 0;
  } catch {
    return false;
  }
};
