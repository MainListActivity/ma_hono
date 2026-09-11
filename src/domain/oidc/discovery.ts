import type { ResolvedIssuerContext } from "../tenants/types";
import type { ManagedResourcePolicy } from "./resource-policy";

export interface DiscoveryMetadata {
  issuer: string;
  jwks_uri: string;
  registration_endpoint: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  grant_types_supported: string[];
  response_types_supported: string[];
  code_challenge_methods_supported: string[];
  scopes_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  resource_indicators_supported?: boolean;
  resource_parameter_supported?: boolean;
  management_registration_endpoint?: string;
  mcp_resource?: string;
}

export const buildDiscoveryMetadata = (
  issuerContext: ResolvedIssuerContext,
  options: { mcpResourcePolicy?: ManagedResourcePolicy | null } = {}
): DiscoveryMetadata => {
  const mcpResourcePolicy = options.mcpResourcePolicy ?? null;

  return {
    issuer: issuerContext.issuer,
    jwks_uri: `${issuerContext.issuer}/jwks.json`,
    registration_endpoint:
      mcpResourcePolicy === null
        ? `${issuerContext.issuer}/connect/register`
        : `${issuerContext.issuer}/connect/mcp/register`,
    authorization_endpoint: `${issuerContext.issuer}/authorize`,
    token_endpoint: `${issuerContext.issuer}/token`,
    revocation_endpoint: `${issuerContext.issuer}/revoke`,
    grant_types_supported: ["authorization_code", "refresh_token"],
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported:
      mcpResourcePolicy === null
        ? ["openid"]
        : ["openid", ...mcpResourcePolicy.scopes],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
      "none"
    ],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    ...(mcpResourcePolicy === null
      ? {}
      : {
          resource_indicators_supported: true,
          resource_parameter_supported: true,
          management_registration_endpoint: `${issuerContext.issuer}/connect/register`,
          mcp_resource: mcpResourcePolicy.resource
        })
  };
};
