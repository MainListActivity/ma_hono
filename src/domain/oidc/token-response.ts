export interface OidcTokenSuccessResponse {
  access_token: string;
  expires_in: number;
  id_token: string;
  scope: string;
  token_type: "Bearer";
}

export interface OidcTokenErrorResponse {
  error: "invalid_client" | "invalid_grant" | "invalid_request" | "server_error" | "unsupported_grant_type";
}
