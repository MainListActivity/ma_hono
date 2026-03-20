import { createApp } from "./app/app";
import { readRuntimeConfig } from "./config/env";

type RuntimeEnv = Record<string, string | undefined>;

export default {
  fetch(request: Request, env: RuntimeEnv, executionContext: ExecutionContext) {
    const runtimeConfig = readRuntimeConfig(env);
    const app = createApp({
      adminBootstrapPassword: runtimeConfig.adminBootstrapPassword,
      managementApiToken: runtimeConfig.managementApiToken,
      platformHost: runtimeConfig.platformHost
    });

    return app.fetch(request, env, executionContext);
  }
};
