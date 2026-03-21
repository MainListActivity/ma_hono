import { createApp } from "./app/app";
import { createRuntimeRepositories } from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig } from "./config/env";
import { sha256Base64Url } from "./lib/hash";

type RuntimeEnv = Record<string, unknown>;

const userSessionCookieName = "user_session";
const userSessionPrefix = "user_session:";

interface RuntimeAuthorizeSessionRecord {
  userId: string;
  expiresAt: string;
}

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
    const repositories = await createRuntimeRepositories(runtimeConfig);
    const app = createApp({
      adminBootstrapPassword: runtimeConfig.adminBootstrapPassword,
      adminWhitelist: runtimeConfig.adminWhitelist,
      adminRepository: repositories.adminRepository,
      auditRepository: repositories.auditRepository,
      authorizationCodeRepository: repositories.authorizationCodeRepository,
      authorizeSessionResolver: async (context) => {
        const sessionToken = getCookieValue(context.req.header("cookie"), userSessionCookieName);

        if (sessionToken === null || sessionToken.length === 0) {
          return null;
        }

        const storedSession = await runtimeConfig.userSessionsKv.get(
          `${userSessionPrefix}${await sha256Base64Url(sessionToken)}`
        );

        if (storedSession === null) {
          return null;
        }

        try {
          const session = JSON.parse(storedSession) as RuntimeAuthorizeSessionRecord;

          if (new Date(session.expiresAt).getTime() <= Date.now()) {
            return null;
          }

          return {
            userId: session.userId
          };
        } catch {
          return null;
        }
      },
      clientRepository: repositories.clientRepository,
      keyRepository: repositories.keyRepository,
      loginChallengeRepository: repositories.loginChallengeRepository,
      managementApiToken: runtimeConfig.managementApiToken,
      platformHost: runtimeConfig.platformHost,
      registrationAccessTokenRepository: repositories.registrationAccessTokenRepository,
      tenantRepository: repositories.tenantRepository
    });

    try {
      return await app.fetch(request, env, executionContext);
    } finally {
      await repositories.close();
    }
  }
};
