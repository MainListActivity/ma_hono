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
