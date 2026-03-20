import type { ResolvedIssuerContext } from "../tenants/types";

export interface DiscoveryMetadata {
  issuer: string;
  jwks_uri: string;
  registration_endpoint: string;
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
}

export const buildDiscoveryMetadata = (
  issuerContext: ResolvedIssuerContext
): DiscoveryMetadata => ({
  issuer: issuerContext.issuer,
  jwks_uri: `${issuerContext.issuer}/jwks.json`,
  registration_endpoint: `${issuerContext.issuer}/connect/register`,
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["ES256"]
});
