import { Hono } from "hono";
import { browserAuthorizationRedirect } from "./app/browser-authorization-redirect";
import { createApp } from "./app/app";
import { createSetupApp } from "./app/setup-app";
import {
  createRuntimeRepositories,
  ensureTenantSigningKeys
} from "./adapters/db/drizzle/runtime";
import { readRuntimeConfig, type RuntimeConfig } from "./config/env";
import {
  loadContentReaderIssuancePolicy,
  loadPlatformConfig
} from "./config/platform-config";
import type { BrowserSessionRepository } from "./domain/authentication/repository";
import {
  browserSessionCookieName
} from "./domain/authentication/session-service";
import type { BrowserSession } from "./domain/authentication/types";
import type { PlatformConfig } from "./config/platform-config";
import type { ContentReaderIssuancePolicy } from "./domain/tokens/content-reader-policy";
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

interface RuntimeInit {
  platformConfig: PlatformConfig | null;
  contentReaderPolicy: ContentReaderIssuancePolicy | null;
  totpEncryptionKey: Uint8Array;
}

// Read-mostly startup inputs (platform config, issuance policy, TOTP key,
// signing-key presence) are memoized per isolate. Every one of these is a
// sequential cross-region D1/R2 call; without memoization each request paid
// ~1s of serial binding latency before routing (observed via Server-Timing).
const RUNTIME_INIT_TTL_MS = 30_000;
let runtimeInit: { at: number; promise: Promise<RuntimeInit> } | null = null;

const startRuntimeInit = async (config: RuntimeConfig): Promise<RuntimeInit> => {
  // Unconfigured deployments take the setup path; keep it cheap and skip the
  // rest of init entirely.
  const platformConfig = await loadPlatformConfig(config.db);
  if (platformConfig === null) {
    return {
      platformConfig: null,
      contentReaderPolicy: null,
      totpEncryptionKey: new Uint8Array(0)
    };
  }
  const repositories = await createRuntimeRepositories(config);
  const totpKeyPromise = (async () => {
    let keyObject = await config.keyMaterialBucket.get("totp-encryption-key");
    if (keyObject === null) {
      const newKey = crypto.getRandomValues(new Uint8Array(32));
      await config.keyMaterialBucket.put("totp-encryption-key", newKey.buffer);
      keyObject = await config.keyMaterialBucket.get("totp-encryption-key");
    }
    return new Uint8Array(await keyObject!.arrayBuffer());
  })();

  const [contentReaderPolicy, totpEncryptionKey] = await Promise.all([
    loadContentReaderIssuancePolicy(config.db),
    totpKeyPromise,
    ensureTenantSigningKeys({
      signer: repositories.signer,
      tenantRepository: repositories.tenantRepository
    })
  ]);
  return { platformConfig, contentReaderPolicy, totpEncryptionKey };
};

const getRuntimeInit = (config: RuntimeConfig): Promise<RuntimeInit> => {
  const now = Date.now();
  if (runtimeInit !== null && now - runtimeInit.at < RUNTIME_INIT_TTL_MS) {
    return runtimeInit.promise;
  }
  const entry = { at: now, promise: startRuntimeInit(config) };
  runtimeInit = entry;
  // Failed inits are never cached so the next request retries immediately.
  entry.promise.catch(() => {
    if (runtimeInit === entry) runtimeInit = null;
  });
  return entry.promise;
};

export default {
  async fetch(request: Request, env: RuntimeEnv, executionContext: ExecutionContext) {
    const marks: string[] = [];
    let markLast = Date.now();
    const mark = (label: string) => {
      const now = Date.now();
      marks.push(`${label};dur=${(now - markLast).toFixed(1)}`);
      markLast = now;
    };
    const runtimeConfig = readRuntimeConfig(env);
    const init = await getRuntimeInit(runtimeConfig);
    mark("init");

    if (init.platformConfig === null) {
      // Never serve the unconfigured setup path from a cached init.
      runtimeInit = null;
      return createSetupApp(runtimeConfig.db).fetch(request);
    }

    const platformConfig = init.platformConfig;
    const contentReaderPolicy = init.contentReaderPolicy;
    const repositories = await createRuntimeRepositories(runtimeConfig);
    const browserSessionRepository = createKvBrowserSessionRepository(runtimeConfig.userSessionsKv);
    const oidcHost = `o.${platformConfig.rootDomain}`;
    const authDomain = `auth.${platformConfig.rootDomain}`;
    const totpEncryptionKey = init.totpEncryptionKey;

    const app = createApp({
      adminBootstrapPasswordHash: platformConfig.adminBootstrapPasswordHash,
      adminWhitelist: platformConfig.adminWhitelist,
      adminRepository: repositories.adminRepository,
      authDomain,
      auditRepository: repositories.auditRepository,
      authorizationCodeRepository: repositories.authorizationCodeRepository,
      consentChallengeRepository: repositories.consentChallengeRepository,
      accessTokenClaimsRepository: repositories.accessTokenClaimsRepository,
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
      keyMaterialBucket: runtimeConfig.keyMaterialBucket,
      keyRepository: repositories.keyRepository,
      loginChallengeLookupRepository: repositories.authenticationLoginChallengeRepository,
      loginChallengeRepository: repositories.loginChallengeRepository,
      managementApiToken: platformConfig.managementApiToken,
      // The protected-resource identifier is the actual MCP endpoint, not the
      // OIDC audience used to validate its bearer token.  Codex and other MCP
      // clients require the metadata resource to match the URL they connect to.
      mcpResource: `https://l.${platformConfig.rootDomain}/api/ops/mcp`,
      contentReaderPolicy,
      oidcHost,
      browserSessionRepository,
      registrationAccessTokenRepository: repositories.registrationAccessTokenRepository,
      accessTokenRevocationRepository: repositories.accessTokenRevocationRepository,
      refreshTokenRepository: repositories.refreshTokenRepository,
      signer: repositories.signer,
      tenantRepository: repositories.tenantRepository,
      totpRepository: repositories.totpRepository,
      mfaPasskeyChallengeRepository: repositories.mfaPasskeyChallengeRepository,
      totpEncryptionKey,
      userRepository: repositories.userRepository
    });
    mark("mkapp");

    // o.{domain} receives OIDC protocol traffic without any prefix.
    // auth.{domain}/api/* receives all API traffic; the Cloudflare route
    // delivers the full path so we strip the /api prefix here.
    const requestHost = new URL(request.url).hostname;
    const customDomainTenant =
      requestHost === oidcHost || requestHost === authDomain
        ? null
        : await repositories.tenantRepository.findByCustomDomain(requestHost);
    mark("custdom");
    const root =
      requestHost === oidcHost || customDomainTenant?.status === "active"
        ? app
        : new Hono().route("/api", app);

    try {
      const browserRedirect = browserAuthorizationRedirect(request, oidcHost, authDomain);
      if (browserRedirect) return browserRedirect;
      const res = await root.fetch(request, env, executionContext);
      mark("handle");
      const withTiming = new Response(res.body, res);
      withTiming.headers.set("Server-Timing", marks.join(", "));
      return withTiming;
    } finally {
      await repositories.close();
    }
  }
};
