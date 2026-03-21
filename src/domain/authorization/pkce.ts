import { sha256Base64Url } from "../../lib/hash";
import type { PkceCodeChallengeMethod } from "./types";

export const validatePkceParameters = ({
  codeChallenge,
  codeChallengeMethod
}: {
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
}):
  | { ok: true; codeChallenge: string; codeChallengeMethod: PkceCodeChallengeMethod }
  | { ok: false; errorDescription: string } => {
  if (
    codeChallenge === null ||
    codeChallenge.length === 0 ||
    codeChallengeMethod === null ||
    codeChallengeMethod.length === 0
  ) {
    return {
      ok: false,
      errorDescription: "PKCE is required"
    };
  }

  if (codeChallengeMethod !== "S256") {
    return {
      ok: false,
      errorDescription: "PKCE code challenge method must be S256"
    };
  }

  return {
    ok: true,
    codeChallenge,
    codeChallengeMethod
  };
};

export const verifyPkce = async ({
  codeChallenge,
  codeChallengeMethod,
  codeVerifier
}: {
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  codeVerifier: string;
}): Promise<boolean> => {
  if (codeChallengeMethod !== "S256") {
    return false;
  }

  return (await sha256Base64Url(codeVerifier)) === codeChallenge;
};
