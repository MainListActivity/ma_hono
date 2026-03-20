import type { AdminRepository } from "./repository";
import type { AdminSession, AdminUser } from "./types";

const textEncoder = new TextEncoder();
const sessionLifetimeMs = 1000 * 60 * 60 * 12;

const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(value));

  return Buffer.from(digest).toString("base64url");
};

export const loginAdmin = async ({
  adminBootstrapPassword,
  adminRepository,
  email,
  password
}: {
  adminBootstrapPassword: string;
  adminRepository: AdminRepository;
  email: string;
  password: string;
}): Promise<{ sessionToken: string; user: AdminUser } | null> => {
  const user = await adminRepository.findUserByEmail(email);

  if (user === null || user.status !== "active") {
    return null;
  }

  if (password !== adminBootstrapPassword) {
    return null;
  }

  const sessionToken = crypto.randomUUID().replaceAll("-", "");
  const session: AdminSession = {
    id: crypto.randomUUID(),
    adminUserId: user.id,
    sessionTokenHash: await sha256(sessionToken),
    expiresAt: new Date(Date.now() + sessionLifetimeMs).toISOString()
  };

  await adminRepository.createSession(session);

  return {
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

  const session = await adminRepository.findSessionByTokenHash(await sha256(token));

  if (session === null) {
    return null;
  }

  return new Date(session.expiresAt).getTime() > Date.now() ? session : null;
};
