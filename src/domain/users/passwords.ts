import { encodeBase64Url } from "../../lib/base64url";

const passwordHashAlgorithm = "pbkdf2_sha256";
const defaultIterations = 120_000;
const derivedKeyLengthBits = 256;
const saltLengthBytes = 16;
const textEncoder = new TextEncoder();

const toArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;

const decodeBase64Url = (value: string): Uint8Array => {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

const derivePasswordDigest = async ({
  iterations,
  password,
  salt
}: {
  iterations: number;
  password: string;
  salt: Uint8Array;
}): Promise<Uint8Array> => {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      iterations
    },
    passwordKey,
    derivedKeyLengthBits
  );

  return new Uint8Array(bits);
};

const timingSafeEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }

  return difference === 0;
};

export const hashPassword = async (password: string): Promise<string> => {
  const salt = crypto.getRandomValues(new Uint8Array(saltLengthBytes));
  const digest = await derivePasswordDigest({
    iterations: defaultIterations,
    password,
    salt
  });

  return [
    passwordHashAlgorithm,
    String(defaultIterations),
    encodeBase64Url(salt),
    encodeBase64Url(digest)
  ].join("$");
};

export const verifyPassword = async ({
  password,
  passwordHash
}: {
  password: string;
  passwordHash: string;
}): Promise<boolean> => {
  const [algorithm, rawIterations, encodedSalt, encodedDigest, ...extra] = passwordHash.split("$");

  if (
    algorithm !== passwordHashAlgorithm ||
    rawIterations === undefined ||
    encodedSalt === undefined ||
    encodedDigest === undefined ||
    extra.length > 0
  ) {
    return false;
  }

  const iterations = Number(rawIterations);

  if (!Number.isInteger(iterations) || iterations <= 0) {
    return false;
  }

  try {
    const salt = decodeBase64Url(encodedSalt);
    const expectedDigest = decodeBase64Url(encodedDigest);
    const actualDigest = await derivePasswordDigest({
      iterations,
      password,
      salt
    });

    return timingSafeEqual(actualDigest, expectedDigest);
  } catch {
    return false;
  }
};
