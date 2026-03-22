// RFC 6238 TOTP implementation using WebCrypto.
// Secret is base32-encoded (no padding).

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const base32ToBytes = (base32: string): Uint8Array => {
  const s = base32.toUpperCase().replace(/=+$/, "");
  const bits: number[] = [];
  for (const ch of s) {
    const val = BASE32_CHARS.indexOf(ch);
    if (val === -1) throw new Error(`Invalid base32 character: ${ch}`);
    for (let i = 4; i >= 0; i--) bits.push((val >> i) & 1);
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j];
    bytes[i] = byte;
  }
  return bytes;
};

const windowToCounter = (windowIndex: number): Uint8Array => {
  const buf = new Uint8Array(8);
  let val = windowIndex;
  for (let i = 7; i >= 0; i--) {
    buf[i] = val & 0xff;
    val = Math.floor(val / 256);
  }
  return buf;
};

export const generateTotpCode = async (
  secretBase32: string,
  windowIndex: number
): Promise<string> => {
  const keyBytes = base32ToBytes(secretBase32);
  const counter = windowToCounter(windowIndex);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, counter);
  const hmac = new Uint8Array(mac);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    1_000_000;
  return code.toString().padStart(6, "0");
};

export type TotpVerifyResult =
  | { kind: "valid"; windowIndex: number }
  | { kind: "invalid_code" }
  | { kind: "replay" };

export const verifyTotpCode = async ({
  code,
  lastUsedWindow,
  now = new Date(),
  period = 30,
  secret
}: {
  code: string;
  lastUsedWindow: number;
  now?: Date;
  period?: number;
  secret: string;
}): Promise<TotpVerifyResult> => {
  const currentWindow = Math.floor(now.getTime() / 1000 / period);
  const windows = [currentWindow - 1, currentWindow, currentWindow + 1];

  for (const w of windows) {
    const expected = await generateTotpCode(secret, w);
    if (expected === code) {
      if (w <= lastUsedWindow) {
        return { kind: "replay" };
      }
      return { kind: "valid", windowIndex: w };
    }
  }

  return { kind: "invalid_code" };
};

export const generateTotpSecret = (): string => {
  // 20 bytes = 160 bits of entropy, base32-encoded
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let result = "";
  for (let i = 0; i < bytes.length; i += 5) {
    const group = bytes.slice(i, i + 5);
    const padded = new Uint8Array(5);
    padded.set(group);
    const indices = [
      (padded[0] >> 3) & 0x1f,
      ((padded[0] << 2) | (padded[1] >> 6)) & 0x1f,
      (padded[1] >> 1) & 0x1f,
      ((padded[1] << 4) | (padded[2] >> 4)) & 0x1f,
      ((padded[2] << 1) | (padded[3] >> 7)) & 0x1f,
      (padded[3] >> 2) & 0x1f,
      ((padded[3] << 3) | (padded[4] >> 5)) & 0x1f,
      padded[4] & 0x1f
    ];
    result += indices.map((i) => BASE32_CHARS[i]).join("");
  }
  return result;
};
