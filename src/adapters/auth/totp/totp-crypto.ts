// AES-256-GCM encrypt/decrypt for TOTP secrets.
// Ciphertext format: base64url(iv[12] || ciphertext || authTag[16])

const IV_LENGTH = 12;

export const encryptTotpSecret = async (
  plaintext: string,
  keyBytes: Uint8Array
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  const result = new Uint8Array(IV_LENGTH + cipherBuf.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(cipherBuf), IV_LENGTH);
  return btoa(String.fromCharCode(...result))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

export const decryptTotpSecret = async (
  ciphertext: string,
  keyBytes: Uint8Array
): Promise<string> => {
  const padded = ciphertext.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  const iv = bytes.slice(0, IV_LENGTH);
  const data = bytes.slice(IV_LENGTH);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plain);
};
