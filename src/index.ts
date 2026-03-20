import { createApp } from "./app/app";
import { createRuntimeRepositories } from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig } from "./config/env";

type RuntimeEnv = Record<string, string | undefined>;

export default {
  async fetch(request: Request, env: RuntimeEnv, executionContext: ExecutionContext) {
    const runtimeConfig = readRuntimeConfig(env);
    const repositories = await createRuntimeRepositories(runtimeConfig);
    const app = createApp({
      adminBootstrapPassword: runtimeConfig.adminBootstrapPassword,
      adminWhitelist: runtimeConfig.adminWhitelist,
      adminRepository: repositories.adminRepository,
      clientRepository: repositories.clientRepository,
      keyRepository: repositories.keyRepository,
      managementApiToken: runtimeConfig.managementApiToken,
      platformHost: runtimeConfig.platformHost,
      tenantRepository: repositories.tenantRepository
    });

    try {
      return await app.fetch(request, env, executionContext);
    } finally {
      await repositories.close();
    }
  }
};
