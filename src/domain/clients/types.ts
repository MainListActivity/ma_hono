export type ClientApplicationType = "web" | "native";

export type ClientTokenEndpointAuthMethod =
  | "client_secret_basic"
  | "client_secret_post"
  | "none";

export type ClientTrustLevel = "first_party_trusted" | "third_party";

export type ClientConsentPolicy = "skip" | "require";

export type ClientProfile = "spa" | "web" | "native";

export type ClientAuthMethodName =
  | "password"
  | "magic_link"
  | "passkey"
  | "google"
  | "apple"
  | "facebook"
  | "wechat";

export const DEFAULT_TOKEN_TTL_SECONDS = 60 * 60;
export const REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS = 60 * 24 * 60 * 60;

export interface ClientPrimaryAuthMethodPolicy {
  enabled: boolean;
  allowRegistration: boolean;
  tokenTtlSeconds?: number;
}

export interface ClientSocialAuthMethodPolicy {
  enabled: boolean;
  tokenTtlSeconds?: number;
}

export interface ClientAuthMethodPolicy {
  clientId: string; // oidc_clients.id (UUID), NOT the OAuth client_id string
  tenantId: string;
  password: ClientPrimaryAuthMethodPolicy;
  emailMagicLink: ClientPrimaryAuthMethodPolicy;
  passkey: ClientPrimaryAuthMethodPolicy;
  google: ClientSocialAuthMethodPolicy;
  apple: ClientSocialAuthMethodPolicy;
  facebook: ClientSocialAuthMethodPolicy;
  wechat: ClientSocialAuthMethodPolicy;
  mfaRequired: boolean;
}

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
  clientProfile: ClientProfile;
  accessTokenAudience: string | null;
  authMethodPolicy?: ClientAuthMethodPolicy;
}

export interface RegisterClientResult {
  client: Client;
  clientSecret: string | null;
  registrationAccessToken: string;
}
