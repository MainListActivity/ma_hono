export interface OidcTokenSuccessResponse {
  access_token: string;
  expires_in: number;
  id_token?: string;
  issued_token_type?: string;
  refresh_token?: string;
  scope: string;
  token_type: "Bearer";
}

export interface OidcTokenErrorResponse {
  error:
    | "invalid_client"
    | "invalid_grant"
    | "invalid_request"
    | "server_error"
    | "unauthorized_client"
    | "unsupported_grant_type";
}
