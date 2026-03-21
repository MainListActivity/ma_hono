import { sha256Base64Url } from "../../lib/hash";
import type { BrowserSessionRepository } from "./repository";
import type { BrowserSession } from "./types";

export const browserSessionCookieName = "user_session";
export const defaultBrowserSessionLifetimeMs = 30 * 24 * 60 * 60 * 1000;

const createOpaqueToken = () => crypto.randomUUID().replaceAll("-", "");

export const buildBrowserSessionCookie = ({
  expiresAt,
  secure = true,
  sessionToken
}: {
  expiresAt: string;
  secure?: boolean;
  sessionToken: string;
}) => {
  const segments = [
    `${browserSessionCookieName}=${sessionToken}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Expires=${new Date(expiresAt).toUTCString()}`
  ];

  if (secure) {
    segments.push("Secure");
  }

  return segments.join("; ");
};

export const createBrowserSession = async ({
  lifetimeMs = defaultBrowserSessionLifetimeMs,
  now = new Date(),
  sessionRepository,
  tenantId,
  userId
}: {
  lifetimeMs?: number;
  now?: Date;
  sessionRepository: BrowserSessionRepository;
  tenantId: string;
  userId: string;
}): Promise<{
  session: BrowserSession;
  sessionToken: string;
}> => {
  const sessionToken = createOpaqueToken();
  const session: BrowserSession = {
    id: crypto.randomUUID(),
    tenantId,
    userId,
    tokenHash: await sha256Base64Url(sessionToken),
    expiresAt: new Date(now.getTime() + lifetimeMs).toISOString(),
    createdAt: now.toISOString()
  };

  await sessionRepository.create(session);

  return {
    session,
    sessionToken
  };
};

export const authenticateBrowserSession = async ({
  now = new Date(),
  sessionRepository,
  sessionToken
}: {
  now?: Date;
  sessionRepository: BrowserSessionRepository;
  sessionToken: string;
}): Promise<BrowserSession | null> => {
  if (sessionToken.trim().length === 0) {
    return null;
  }

  const session = await sessionRepository.findByTokenHash(await sha256Base64Url(sessionToken));

  if (session === null) {
    return null;
  }

  return new Date(session.expiresAt).getTime() > now.getTime() ? session : null;
};
