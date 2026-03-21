export type ClientApplicationType = "web" | "native";

export type ClientTokenEndpointAuthMethod =
  | "client_secret_basic"
  | "client_secret_post"
  | "none";

export type ClientTrustLevel = "first_party_trusted" | "third_party";

export type ClientConsentPolicy = "skip" | "require";

export interface Client {
  id: string;
  tenantId: string;
  clientId: string;
  clientName: string;
  applicationType: ClientApplicationType;
  grantTypes: string[];
  redirectUris: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: ClientTokenEndpointAuthMethod;
  clientSecretHash: string | null;
  trustLevel: ClientTrustLevel;
  consentPolicy: ClientConsentPolicy;
}

export interface RegisterClientResult {
  client: Client;
  clientSecret: string | null;
  registrationAccessToken: string;
}
