import type { ResolvedIssuerContext } from "../tenants/types";
import type { ClientRepository } from "./repository";
import {
  dynamicClientRegistrationSchema,
  type DynamicClientRegistrationInput
} from "./registration-schema";
import type { Client, RegisterClientResult } from "./types";

const textEncoder = new TextEncoder();

const createRandomToken = () => crypto.randomUUID().replaceAll("-", "");

const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(value));

  return Buffer.from(digest).toString("base64url");
};

const requiresClientSecret = (authMethod: DynamicClientRegistrationInput["token_endpoint_auth_method"]) =>
  authMethod !== "none" && authMethod !== "private_key_jwt";

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
    clientSecretHash: clientSecret === null ? null : await sha256(clientSecret),
    registrationAccessTokenHash: await sha256(registrationAccessToken)
  };

  await clientRepository.create(client);

  return {
    client,
    clientSecret,
    registrationAccessToken
  };
};
