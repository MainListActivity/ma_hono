import type { ResolvedIssuerContext } from "../tenants/types";
import { sha256Base64Url } from "../../lib/hash";
import type { ClientRepository } from "./repository";
import {
  dynamicClientRegistrationSchema,
  type DynamicClientRegistrationInput
} from "./registration-schema";
import type { Client, RegisterClientResult } from "./types";

const createRandomToken = () => crypto.randomUUID().replaceAll("-", "");

const requiresClientSecret = (authMethod: DynamicClientRegistrationInput["token_endpoint_auth_method"]) =>
  authMethod !== "none";

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
    consentPolicy: payload.consent_policy
  };

  await clientRepository.create(client);

  return {
    client,
    clientSecret,
    registrationAccessToken
  };
};
