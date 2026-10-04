import type { AdminRepository } from "./repository";
import type {
  AdminAuthorization,
  AdminServicePrincipal,
  AdminSession,
  AdminUser,
  ServicePrincipalScope
} from "./types";
import { SERVICE_PRINCIPAL_SCOPES } from "./types";
import { verifyPasswordPbkdf2 } from "../../lib/pbkdf2";
import { encodeBase64Url } from "../../lib/base64url";

const sessionLifetimeMs = 1000 * 60 * 60 * 12;
import { sha256Base64Url } from "../../lib/hash";

export const loginAdmin = async ({
  adminBootstrapPasswordHash,
  adminWhitelist,
  adminRepository,
  email,
  password
}: {
  adminBootstrapPasswordHash: string;
  adminWhitelist: string[];
  adminRepository: AdminRepository;
  email: string;
  password: string;
}): Promise<
  | { ok: true; sessionToken: string; user: AdminUser }
  | { ok: false; reason: "forbidden" | "unauthorized" }
> => {
  if (!adminWhitelist.includes(email)) {
    return { ok: false, reason: "forbidden" };
  }

  const isValid = await verifyPasswordPbkdf2(password, adminBootstrapPasswordHash);
  if (!isValid) {
    return { ok: false, reason: "unauthorized" };
  }

  const repositoryUser = await adminRepository.findUserByEmail(email);
  if (repositoryUser !== null && repositoryUser.status !== "active") {
    return { ok: false, reason: "forbidden" };
  }

  const user =
    repositoryUser ??
    ({
      id: `whitelist:${email}`,
      email,
      status: "active"
    } satisfies AdminUser);

  const sessionToken = crypto.randomUUID().replaceAll("-", "");
  const session: AdminSession = {
    id: crypto.randomUUID(),
    adminUserId: user.id,
    sessionTokenHash: await sha256Base64Url(sessionToken),
    expiresAt: new Date(Date.now() + sessionLifetimeMs).toISOString()
  };

  await adminRepository.createSession(session);

  return {
    ok: true,
    sessionToken,
    user
  };
};

export const authenticateAdminSession = async ({
  adminRepository,
  authorizationHeader
}: {
  adminRepository: AdminRepository;
  authorizationHeader: string | undefined;
}): Promise<AdminSession | null> => {
  const token = authorizationHeader?.startsWith("Bearer ")
    ? authorizationHeader.slice("Bearer ".length)
    : null;

  if (token === null) {
    return null;
  }

  const session = await adminRepository.findSessionByTokenHash(await sha256Base64Url(token));

  if (session === null) {
    return null;
  }

  return new Date(session.expiresAt).getTime() > Date.now() ? session : null;
};

const parseBearerToken = (authorizationHeader: string | undefined): string | null => {
  if (authorizationHeader === undefined || !authorizationHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authorizationHeader.slice("Bearer ".length).trim();
  return token.length === 0 ? null : token;
};

export const resolveAdminAuthorization = async ({
  adminRepository,
  authorizationHeader
}: {
  adminRepository: AdminRepository;
  authorizationHeader: string | undefined;
}): Promise<
  | { ok: true; auth: AdminAuthorization }
  | { ok: false; status: 401 | 403; error: "unauthorized" | "forbidden" }
> => {
  const token = parseBearerToken(authorizationHeader);
  if (token === null) {
    return { ok: false, status: 401, error: "unauthorized" };
  }

  const tokenHash = await sha256Base64Url(token);
  const session = await adminRepository.findSessionByTokenHash(tokenHash);

  if (session !== null && new Date(session.expiresAt).getTime() > Date.now()) {
    return { ok: true, auth: { kind: "session", session } };
  }

  const principal = await adminRepository.findServicePrincipalByTokenHash(tokenHash);
  if (principal === null) {
    return { ok: false, status: 401, error: "unauthorized" };
  }

  if (principal.status === "revoked") {
    return { ok: false, status: 403, error: "forbidden" };
  }

  return { ok: true, auth: { kind: "service_principal", principal } };
};

export const mintServicePrincipalToken = (): string => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
};

export const parseServicePrincipalScopes = (
  scopes: unknown
): ServicePrincipalScope[] | null => {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return null;
  }

  const allowed = new Set<string>(SERVICE_PRINCIPAL_SCOPES);
  const normalized: ServicePrincipalScope[] = [];

  for (const scope of scopes) {
    if (typeof scope !== "string" || !allowed.has(scope)) {
      return null;
    }

    if (!normalized.includes(scope as ServicePrincipalScope)) {
      normalized.push(scope as ServicePrincipalScope);
    }
  }

  return normalized;
};

export const mintServicePrincipal = async ({
  adminRepository,
  label,
  scopes,
  createdBy,
  now = new Date()
}: {
  adminRepository: AdminRepository;
  label: string;
  scopes: ServicePrincipalScope[];
  createdBy: string;
  now?: Date;
}): Promise<{ principal: AdminServicePrincipal; token: string }> => {
  const token = mintServicePrincipalToken();
  const principal: AdminServicePrincipal = {
    id: crypto.randomUUID(),
    label,
    tokenHash: await sha256Base64Url(token),
    scopes,
    status: "active",
    createdAt: now.toISOString(),
    revokedAt: null,
    createdBy
  };

  await adminRepository.createServicePrincipal(principal);

  return { principal, token };
};

export const toPublicServicePrincipal = (principal: AdminServicePrincipal) => ({
  id: principal.id,
  label: principal.label,
  scopes: principal.scopes,
  status: principal.status,
  created_at: principal.createdAt,
  revoked_at: principal.revokedAt,
  created_by: principal.createdBy
});

export const auditActorFromAuthorization = (
  auth: AdminAuthorization
): { actorType: "admin_user" | "service_principal"; actorId: string } =>
  auth.kind === "session"
    ? { actorType: "admin_user", actorId: auth.session.adminUserId }
    : { actorType: "service_principal", actorId: auth.principal.id };
