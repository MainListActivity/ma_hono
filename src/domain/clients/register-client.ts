import type { ResolvedIssuerContext } from "../tenants/types";
import { sha256Base64Url } from "../../lib/hash";
import type { AccessTokenClaimsRepository } from "./access-token-claims-repository";
import type { AccessTokenCustomClaim } from "./access-token-claims-types";
import {
  adminClientRegistrationSchema,
  type AdminClientRegistrationInput
} from "./admin-registration-schema";
import type { ClientRepository } from "./repository";
import {
  dynamicClientRegistrationSchema,
  type DynamicClientRegistrationInput
} from "./registration-schema";
import type { Client, RegisterClientResult } from "./types";

const createRandomToken = () => crypto.randomUUID().replaceAll("-", "");

const requiresClientSecret = (
  authMethod:
    | DynamicClientRegistrationInput["token_endpoint_auth_method"]
    | AdminClientRegistrationInput["token_endpoint_auth_method"]
) => authMethod !== "none";

export const registerClient = async ({
  clientRepository,
  input,
  issuerContext
}: {
  clientRepository: ClientRepository;
  input: unknown;
  issuerContext: ResolvedIssuerContext;
}): Promise<RegisterClientResult> => {
  const payload = dynamicClientRegistrationSchema.parse(input);
  const clientId = crypto.randomUUID();
  const clientSecret = requiresClientSecret(payload.token_endpoint_auth_method)
    ? createRandomToken()
    : null;
  const registrationAccessToken = createRandomToken();

  const client: Client = {
    id: crypto.randomUUID(),
    tenantId: issuerContext.tenant.id,
    clientId,
    clientName: payload.client_name,
    applicationType: payload.application_type,
    grantTypes: payload.grant_types,
    redirectUris: payload.redirect_uris,
    responseTypes: payload.response_types,
    tokenEndpointAuthMethod: payload.token_endpoint_auth_method,
    clientSecretHash: clientSecret === null ? null : await sha256Base64Url(clientSecret),
    trustLevel: payload.trust_level,
    consentPolicy: payload.consent_policy,
    clientProfile: "web",
    accessTokenAudience: null
  };

  await clientRepository.create(client);

  return {
    client,
    clientSecret,
    registrationAccessToken
  };
};

export const registerClientFromAdmin = async ({
  accessTokenClaimsRepository,
  clientRepository,
  input,
  issuerContext
}: {
  accessTokenClaimsRepository: AccessTokenClaimsRepository;
  clientRepository: ClientRepository;
  input: unknown;
  issuerContext: ResolvedIssuerContext;
}): Promise<RegisterClientResult> => {
  const payload = adminClientRegistrationSchema.parse(input);
  const clientId = crypto.randomUUID();
  const clientSecret = requiresClientSecret(payload.token_endpoint_auth_method)
    ? createRandomToken()
    : null;
  const registrationAccessToken = createRandomToken();
  const internalId = crypto.randomUUID();
  const now = new Date().toISOString();

  const client: Client = {
    id: internalId,
    tenantId: issuerContext.tenant.id,
    clientId,
    clientName: payload.client_name,
    applicationType: payload.application_type,
    grantTypes: payload.grant_types,
    redirectUris: payload.redirect_uris,
    responseTypes: payload.response_types,
    tokenEndpointAuthMethod: payload.token_endpoint_auth_method,
    clientSecretHash: clientSecret === null ? null : await sha256Base64Url(clientSecret),
    trustLevel: payload.trust_level,
    consentPolicy: payload.consent_policy,
    clientProfile: payload.client_profile,
    accessTokenAudience: payload.access_token_audience ?? null
  };

  await clientRepository.create(client);

  const claimInputs = payload.access_token_custom_claims ?? [];

  if (claimInputs.length > 0) {
    const claims: AccessTokenCustomClaim[] = claimInputs.map((claim) => ({
      id: crypto.randomUUID(),
      clientId: internalId,
      tenantId: issuerContext.tenant.id,
      claimName: claim.claim_name,
      sourceType: claim.source_type,
      fixedValue:
        claim.source_type === "fixed" ? (claim.fixed_value ?? null) : null,
      userField:
        claim.source_type === "user_field"
          ? ((claim.user_field ?? null) as AccessTokenCustomClaim["userField"])
          : null,
      createdAt: now,
      updatedAt: now
    }));

    await accessTokenClaimsRepository.createMany(claims);
  }

  return {
    client,
    clientSecret,
    registrationAccessToken
  };
};
