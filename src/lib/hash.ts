import { encodeBase64Url } from "./base64url";

const textEncoder = new TextEncoder();

export const sha256Base64Url = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(value));

  return encodeBase64Url(digest);
};
