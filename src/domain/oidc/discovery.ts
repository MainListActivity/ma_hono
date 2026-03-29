import type { ResolvedIssuerContext } from "../tenants/types";

export interface DiscoveryMetadata {
  issuer: string;
  jwks_uri: string;
  registration_endpoint: string;
  authorization_endpoint: string;
  token_endpoint: string;
  grant_types_supported: string[];
  response_types_supported: string[];
  code_challenge_methods_supported: string[];
  scopes_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
}

export const buildDiscoveryMetadata = (
  issuerContext: ResolvedIssuerContext
): DiscoveryMetadata => ({
  issuer: issuerContext.issuer,
  jwks_uri: `${issuerContext.issuer}/jwks.json`,
  registration_endpoint: `${issuerContext.issuer}/connect/register`,
  authorization_endpoint: `${issuerContext.issuer}/authorize`,
  token_endpoint: `${issuerContext.issuer}/token`,
  grant_types_supported: ["authorization_code", "refresh_token"],
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["openid"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"]
});
