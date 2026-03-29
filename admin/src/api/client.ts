// SPA and Worker API share the same origin (auth.{domain}), so use a relative base path.
const BASE_URL = "/api";

export interface TenantSummary {
  id: string;
  slug: string;
  display_name: string;
  status: "active" | "disabled";
  issuer: string | null;
}

export interface UserSummary {
  id: string;
  email: string;
  display_name: string;
  status: string;
}

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
  }
}

const authHeaders = (token: string) => ({
  Authorization: `Bearer ${token}`,
  "Content-Type": "application/json"
});

const checkOk = async (res: Response) => {
  if (res.status === 401) {
    sessionStorage.removeItem("admin_session_token");
    window.location.href = "/login";
    throw new ApiError(401, "unauthorized");
  }
  if (!res.ok) {
    throw new ApiError(res.status, `Request failed: ${res.status}`);
  }
  return res;
};

export const login = async (email: string, password: string) => {
  const res = await fetch(`${BASE_URL}/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) throw new ApiError(res.status, "Login failed");
  return res.json() as Promise<{ email: string; session_token: string }>;
};

export const listTenants = async (token: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<{ tenants: TenantSummary[] }>;
};

export const getTenant = async (token: string, tenantId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<TenantSummary>;
};

export const updateTenant = async (
  token: string,
  tenantId: string,
  payload: { display_name?: string; status?: string; primary_issuer_url?: string }
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify(payload)
    })
  );
  return res.json() as Promise<TenantSummary>;
};

export const deleteTenant = async (token: string, tenantId: string) => {
  await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}`, {
      method: "DELETE",
      headers: authHeaders(token)
    })
  );
};

export const rotateTenantKey = async (
  token: string,
  tenantId: string
): Promise<{ kid: string; alg: string; rotated_at: string }> => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/keys/rotate`, {
      method: "POST",
      headers: authHeaders(token)
    })
  );
  return res.json() as Promise<{ kid: string; alg: string; rotated_at: string }>;
};

export const createTenant = async (token: string, slug: string, displayName: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ slug, display_name: displayName })
    })
  );
  return res.json() as Promise<{ id: string; slug: string; display_name: string; issuer: string }>;
};

export const listUsers = async (token: string, tenantId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/users`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<{ users: UserSummary[] }>;
};

export const provisionUser = async (
  token: string,
  tenantId: string,
  email: string,
  displayName: string,
  username?: string
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/users`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        email,
        display_name: displayName,
        ...(username ? { username } : {})
      })
    })
  );
  return res.json();
};

// ─── Client management API ───────────────────────────────────────────────────

export interface ClientSummary {
  id: string;
  client_id: string;
  client_name: string;
  application_type: "web" | "native";
  client_profile: "spa" | "web" | "native";
  access_token_audience: string | null;
  access_token_custom_claims_count?: number;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  trust_level: string;
  consent_policy: string;
  auth_method_policy: AuthMethodPolicyWire | null;
}

export interface AuthMethodPolicyWire {
  password: { enabled: boolean; allow_registration: boolean };
  magic_link: { enabled: boolean; allow_registration: boolean };
  passkey: { enabled: boolean; allow_registration: boolean };
  google: { enabled: boolean };
  apple: { enabled: boolean };
  facebook: { enabled: boolean };
  wechat: { enabled: boolean };
  mfa_required: boolean;
}

export const listClients = async (token: string, tenantId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients`, { headers: authHeaders(token) })
  );
  return res.json() as Promise<{ clients: ClientSummary[] }>;
};

export interface ClientDetail extends ClientSummary {
  access_token_custom_claims?: {
    claim_name: string;
    source_type: "fixed" | "user_field";
    fixed_value: string | null;
    user_field: string | null;
  }[];
}

export const getClient = async (token: string, tenantId: string, clientId: string) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}`, {
      headers: authHeaders(token)
    })
  );
  return res.json() as Promise<ClientDetail>;
};

export const updateClientAuthMethodPolicy = async (
  token: string,
  tenantId: string,
  clientId: string,
  policy: Partial<AuthMethodPolicyWire>
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}/auth-method-policy`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify(policy)
    })
  );
  return res.json() as Promise<{ auth_method_policy: AuthMethodPolicyWire }>;
};

export const registerUser = async (
  tenantSlug: string,
  payload: {
    login_challenge: string;
    email: string;
    username?: string;
    password: string;
  }
): Promise<Response> => {
  return fetch(`${BASE_URL}/t/${tenantSlug}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
};

export const createClient = async (
  token: string,
  tenantId: string,
  payload: {
    client_name: string;
    client_profile: "spa" | "web" | "native";
    application_type: "web" | "native";
    redirect_uris: string[];
    token_endpoint_auth_method: string;
    grant_types: string[];
    response_types: string[];
    access_token_audience?: string;
    access_token_custom_claims?: {
      claim_name: string;
      source_type: "fixed" | "user_field";
      fixed_value?: string;
      user_field?: string;
    }[];
  }
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify(payload)
    })
  );
  return res.json() as Promise<ClientSummary & { client_secret?: string }>;
};

export const deleteClient = async (token: string, tenantId: string, clientId: string) => {
  await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}`, {
      method: "DELETE",
      headers: authHeaders(token)
    })
  );
};

export const updateClient = async (
  token: string,
  tenantId: string,
  clientId: string,
  payload: {
    client_name?: string;
    client_profile?: "spa" | "web" | "native";
    application_type?: "web" | "native";
    redirect_uris?: string[];
    token_endpoint_auth_method?: string;
    access_token_audience?: string | null;
    access_token_custom_claims?: {
      claim_name: string;
      source_type: "fixed" | "user_field";
      fixed_value?: string;
      user_field?: string;
    }[];
  }
) => {
  const res = await checkOk(
    await fetch(`${BASE_URL}/admin/tenants/${tenantId}/clients/${clientId}`, {
      method: "PATCH",
      headers: authHeaders(token),
      body: JSON.stringify(payload)
    })
  );
  return res.json() as Promise<ClientSummary>;
};

// ─── Tenant login API ────────────────────────────────────────────────────────

export interface ChallengeInfo {
  tenant_display_name: string;
  methods: { method: string; allow_registration: boolean }[];
}

export const getChallengeInfo = async (
  tenantSlug: string,
  loginChallenge: string
): Promise<ChallengeInfo> => {
  const url = `${BASE_URL}/login/${tenantSlug}/challenge-info?login_challenge=${encodeURIComponent(loginChallenge)}`;
  const res = await fetch(url);
  if (!res.ok) throw new ApiError(res.status, "Failed to load challenge info");
  return res.json() as Promise<ChallengeInfo>;
};

export const loginWithPassword = async (
  tenantSlug: string,
  loginChallenge: string,
  username: string,
  password: string
): Promise<Response> => {
  const body = new URLSearchParams({ login_challenge: loginChallenge, username, password });
  return fetch(`${BASE_URL}/login/${tenantSlug}/password`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });
};

export const requestMagicLink = async (
  tenantSlug: string,
  loginChallenge: string,
  email: string
): Promise<void> => {
  const body = new URLSearchParams({ login_challenge: loginChallenge, email });
  const res = await fetch(`${BASE_URL}/login/${tenantSlug}/magic-link/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });
  if (!res.ok) throw new ApiError(res.status, "Failed to send magic link");
};

export const consumeMagicLink = async (
  tenantSlug: string,
  token: string
): Promise<Response> => {
  const body = new URLSearchParams({ token });
  return fetch(`${BASE_URL}/login/${tenantSlug}/magic-link/consume`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
};

export const startPasskeyLogin = async (
  tenantSlug: string,
  loginChallenge: string
): Promise<unknown> => {
  const body = new URLSearchParams({ login_challenge: loginChallenge });
  const res = await fetch(`${BASE_URL}/login/${tenantSlug}/passkey/start`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });
  if (!res.ok) throw new ApiError(res.status, "Failed to start passkey login");
  return res.json();
};

export const finishPasskeyLogin = async (
  tenantSlug: string,
  assertionSessionId: string,
  credential: PublicKeyCredential
): Promise<Response> => {
  const assertion = credential.response as AuthenticatorAssertionResponse;
  const toBase64 = (buf: ArrayBuffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)));
  return fetch(`${BASE_URL}/login/${tenantSlug}/passkey/finish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      assertion_session_id: assertionSessionId,
      credential_id: credential.id,
      sign_count: 0, // will be overridden by server if authenticator reports it
      response: {
        authenticator_data: toBase64(assertion.authenticatorData),
        client_data_json: toBase64(assertion.clientDataJSON),
        signature: toBase64(assertion.signature)
      }
    }),
  });
};

// ─── MFA API ─────────────────────────────────────────────────────────────────

export interface MfaRequiredResponse {
  mfa_state: "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";
  login_challenge: string;
  has_totp_fallback?: boolean;
}

export const mfaTotpVerify = async (
  tenantSlug: string,
  loginChallenge: string,
  code: string
): Promise<Response> =>
  fetch(`${BASE_URL}/login/${tenantSlug}/mfa/totp/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_challenge: loginChallenge, code }),
  });

export const mfaPasskeyStart = async (
  tenantSlug: string,
  loginChallenge: string
): Promise<{ challenge: string; allowed_credentials: string[] }> => {
  const res = await fetch(`${BASE_URL}/login/${tenantSlug}/mfa/passkey/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_challenge: loginChallenge })
  });
  if (!res.ok) throw new ApiError(res.status, "Failed to start passkey step-up");
  return res.json() as Promise<{ challenge: string; allowed_credentials: string[] }>;
};

export const mfaPasskeyFinish = async (
  tenantSlug: string,
  loginChallenge: string,
  rawNonce: string,        // the raw base64url nonce from mfaPasskeyStart — NOT yet hashed
  credential: PublicKeyCredential
): Promise<Response> => {
  const assertion = credential.response as AuthenticatorAssertionResponse;
  const toBase64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  // The server looks up MfaPasskeyChallenge by SHA-256(nonce), so hash before sending
  const nonceBytes = Uint8Array.from(atob(rawNonce.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const hashBuf = await crypto.subtle.digest("SHA-256", nonceBytes);
  const challengeHash = btoa(String.fromCharCode(...new Uint8Array(hashBuf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return fetch(`${BASE_URL}/login/${tenantSlug}/mfa/passkey/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      login_challenge: loginChallenge,
      challenge_hash: challengeHash,
      challenge: rawNonce,  // also send the raw nonce for WebAuthn expectedChallenge
      credential_id: credential.id,
      response: {
        authenticator_data: toBase64(assertion.authenticatorData),
        client_data_json: toBase64(assertion.clientDataJSON),
        signature: toBase64(assertion.signature)
      }
    }),
  });
};

export const mfaSwitchToTotp = async (
  tenantSlug: string,
  loginChallenge: string
): Promise<void> => {
  const res = await fetch(`${BASE_URL}/login/${tenantSlug}/mfa/switch-to-totp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_challenge: loginChallenge })
  });
  if (!res.ok) throw new ApiError(res.status, "Failed to switch to TOTP");
};

export const mfaEnrollStart = async (
  tenantSlug: string,
  loginChallenge: string
): Promise<{ provisioning_uri: string; secret: string }> => {
  const res = await fetch(`${BASE_URL}/login/${tenantSlug}/mfa/totp/enroll/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_challenge: loginChallenge })
  });
  if (!res.ok) throw new ApiError(res.status, "Failed to start enrollment");
  return res.json() as Promise<{ provisioning_uri: string; secret: string }>;
};

export const mfaEnrollFinish = async (
  tenantSlug: string,
  loginChallenge: string,
  code: string
): Promise<Response> =>
  fetch(`${BASE_URL}/login/${tenantSlug}/mfa/totp/enroll/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_challenge: loginChallenge, code }),
  });
