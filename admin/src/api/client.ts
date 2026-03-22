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

// ─── Tenant login API ────────────────────────────────────────────────────────

export interface ChallengeInfo {
  tenant_display_name: string;
  methods: ("password" | "magic_link" | "passkey")[];
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
    body,
    redirect: "manual"
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
    redirect: "manual"
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
    redirect: "manual"
  });
};
