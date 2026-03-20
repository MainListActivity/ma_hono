import type { AdminRepository } from "./repository";
import type { AdminSession, AdminUser } from "./types";

const sessionLifetimeMs = 1000 * 60 * 60 * 12;
import { sha256Base64Url } from "../../lib/hash";

export const loginAdmin = async ({
  adminBootstrapPassword,
  adminWhitelist,
  adminRepository,
  email,
  password
}: {
  adminBootstrapPassword: string;
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

  if (password !== adminBootstrapPassword) {
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
