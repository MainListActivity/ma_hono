import { Hono } from "hono";
import { createApp } from "./app/app";
import { createSetupApp } from "./app/setup-app";
import { createRuntimeRepositories } from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig } from "./config/env";
import { loadPlatformConfig } from "./config/platform-config";
import type { BrowserSessionRepository } from "./domain/authentication/repository";
import {
  browserSessionCookieName
} from "./domain/authentication/session-service";
import type { BrowserSession } from "./domain/authentication/types";
import { sha256Base64Url } from "./lib/hash";

type RuntimeEnv = Record<string, unknown>;

const userSessionPrefix = "user_session:";

const createKvBrowserSessionRepository = (kv: KVNamespace): BrowserSessionRepository => ({
  async create(session: BrowserSession): Promise<void> {
    const expirationTtl = Math.max(
      60,
      Math.ceil((new Date(session.expiresAt).getTime() - Date.now()) / 1000)
    );

    await kv.put(`${userSessionPrefix}${session.tokenHash}`, JSON.stringify(session), {
      expirationTtl
    });
  },

  async findByTokenHash(tokenHash: string): Promise<BrowserSession | null> {
    const storedSession = await kv.get(`${userSessionPrefix}${tokenHash}`);

    if (storedSession === null) {
      return null;
    }

    try {
      return JSON.parse(storedSession) as BrowserSession;
    } catch {
      return null;
    }
  }
});

const getCookieValue = (cookieHeader: string | null | undefined, name: string) => {
  if (cookieHeader === undefined || cookieHeader === null) {
    return null;
  }

  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValueParts] = part.trim().split("=");

    if (rawName === name) {
      return rawValueParts.join("=");
    }
  }

  return null;
};

export default {
  async fetch(request: Request, env: RuntimeEnv, executionContext: ExecutionContext) {
    const runtimeConfig = readRuntimeConfig(env);
    const platformConfig = await loadPlatformConfig(runtimeConfig.db);

    if (platformConfig === null) {
      return createSetupApp(runtimeConfig.db).fetch(request);
    }

    const repositories = await createRuntimeRepositories(runtimeConfig);
    const browserSessionRepository = createKvBrowserSessionRepository(runtimeConfig.userSessionsKv);
    const oidcHost = `o.${platformConfig.rootDomain}`;
    const authDomain = `auth.${platformConfig.rootDomain}`;

    const totpKeyObject = await runtimeConfig.keyMaterialBucket.get("totp-encryption-key");
    if (totpKeyObject === null) throw new Error("TOTP encryption key not found in key store (totp-encryption-key)");
    const totpEncryptionKey = new Uint8Array(await totpKeyObject.arrayBuffer());

    const app = createApp({
      adminBootstrapPasswordHash: platformConfig.adminBootstrapPasswordHash,
      adminWhitelist: platformConfig.adminWhitelist,
      adminRepository: repositories.adminRepository,
      authDomain,
      auditRepository: repositories.auditRepository,
      authorizationCodeRepository: repositories.authorizationCodeRepository,
      authorizeSessionResolver: async (context) => {
        const sessionToken = getCookieValue(context.req.header("cookie"), browserSessionCookieName);

        if (sessionToken === null || sessionToken.length === 0) {
          return null;
        }

        const tokenHash = await sha256Base64Url(sessionToken);
        const session = await browserSessionRepository.findByTokenHash(tokenHash);

        if (session === null) {
          return null;
        }

        if (new Date(session.expiresAt).getTime() <= Date.now()) {
          return null;
        }

        return {
          tenantId: session.tenantId,
          userId: session.userId
        };
      },
      clientAuthMethodPolicyRepository: repositories.clientAuthMethodPolicyRepository,
      clientRepository: repositories.clientRepository,
      keyRepository: repositories.keyRepository,
      loginChallengeLookupRepository: repositories.authenticationLoginChallengeRepository,
      loginChallengeRepository: repositories.loginChallengeRepository,
      managementApiToken: platformConfig.managementApiToken,
      oidcHost,
      browserSessionRepository,
      registrationAccessTokenRepository: repositories.registrationAccessTokenRepository,
      signer: repositories.signer,
      tenantRepository: repositories.tenantRepository,
      totpRepository: repositories.totpRepository,
      mfaPasskeyChallengeRepository: repositories.mfaPasskeyChallengeRepository,
      totpEncryptionKey,
      userRepository: repositories.userRepository
    });

    // o.{domain} receives OIDC protocol traffic without any prefix.
    // auth.{domain}/api/* receives all API traffic; the Cloudflare route
    // delivers the full path so we strip the /api prefix here.
    const requestHost = new URL(request.url).hostname;
    const root =
      requestHost === oidcHost
        ? app
        : new Hono().route("/api", app);

    try {
      return await root.fetch(request, env, executionContext);
    } finally {
      await repositories.close();
    }
  }
};
