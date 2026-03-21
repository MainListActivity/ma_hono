import { createApp } from "./app/app";
import { createRuntimeRepositories } from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig } from "./config/env";

type RuntimeEnv = Record<string, unknown>;

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
