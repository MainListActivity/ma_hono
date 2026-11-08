import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAccessTokenRevocationRepository } from "../../src/adapters/db/memory/memory-access-token-revocation-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryRefreshTokenRepository } from "../../src/adapters/db/memory/memory-refresh-token-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import type { User } from "../../src/domain/users/types";
import { sha256Base64Url } from "../../src/lib/hash";

const ISSUER = "https://idp.example.test/t/acme";
const TOKEN_URL = "https://idp.example.test/t/acme/token";
const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const AGENT_ID_TOKEN_TYPE = "urn:ma-hono:params:oauth:token-type:agent-id";
const REMOTE_GRANT_CODE_TOKEN_TYPE = "urn:ma-hono:params:oauth:token-type:remote-grant-code";

const tenantRepository = new MemoryTenantRepository([
  {
    id: "tenant_acme",
    slug: "acme",
    displayName: "Acme",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_acme",
        issuerType: "platform_path",
        issuerUrl: ISSUER,
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  }
]);

const createSigner = async (): Promise<{
  material: SigningKeyMaterial;
  signer: SigningKeySigner;
}> => {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true
  });
  const material: SigningKeyMaterial = {
    key: {
      id: "key_acme",
      tenantId: "tenant_acme",
      kid: "kid-acme",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      publicJwk: {
        ...(await exportJWK(publicKey)),
        alg: "RS256",
        kid: "kid-acme",
        use: "sig"
      }
    },
    privateJwk: {
      ...(await exportJWK(privateKey)),
      alg: "RS256",
      kid: "kid-acme"
    }
  };

  return {
    material,
    signer: {
      async ensureActiveSigningKeyMaterial() {
        return material;
      },
      async loadActiveSigningKeyMaterial() {
        return material;
      }
    }
  };
};

const createClient = async ({
  agentClaimSourceClientId = null,
  agentTokenExchangeEnabled = true,
  accessTokenAudience = "https://api.acme.test",
  authMethod = "client_secret_basic",
  clientId = "company_runner",
  grantTypes = ["client_credentials"],
  secret = "runner-secret",
  tenantId = "tenant_acme"
}: {
  agentClaimSourceClientId?: string | null;
  agentTokenExchangeEnabled?: boolean;
  accessTokenAudience?: string | null;
  authMethod?: Client["tokenEndpointAuthMethod"];
  clientId?: string;
  grantTypes?: string[];
  secret?: string | null;
  tenantId?: string;
} = {}): Promise<Client> => ({
  id: `record_${clientId}`,
  tenantId,
  clientId,
  clientName: clientId,
  applicationType: "web",
  grantTypes,
  redirectUris: [],
  responseTypes: [],
  tokenEndpointAuthMethod: authMethod,
  clientSecretHash: secret === null ? null : await sha256Base64Url(secret),
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "web",
  accessTokenAudience,
  agentTokenExchangeEnabled,
  agentClaimSourceClientId
});

const makeUser = (overrides: Partial<User> & Pick<User, "id">): User => ({
  tenantId: "tenant_acme",
  email: `${overrides.id}@agents.example.test`,
  emailVerified: false,
  username: null,
  displayName: overrides.id,
  status: "active",
  kind: "agent",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

const makeClaim = (
  overrides: Partial<AccessTokenCustomClaim>
): AccessTokenCustomClaim => ({
  id: "claim_1",
  clientId: "record_company_agent_claims",
  tenantId: "tenant_acme",
  claimName: "custom",
  sourceType: "fixed",
  fixedValue: null,
  userField: null,
  hookField: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

const createTestApp = async ({
  clients,
  claims = [],
  users = []
}: {
  clients: Client[];
  claims?: AccessTokenCustomClaim[];
  users?: User[];
}) => {
  const { material, signer } = await createSigner();
  const auditRepository = new MemoryAuditRepository();
  const accessTokenClaimsRepository = new MemoryAccessTokenClaimsRepository();

  if (claims.length > 0) {
    await accessTokenClaimsRepository.createMany(claims);
  }

  const app = createApp({
    accessTokenClaimsRepository,
    auditRepository,
    authorizationCodeRepository: new MemoryAuthorizationCodeRepository(),
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository: new MemoryClientRepository(clients),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    accessTokenRevocationRepository: new MemoryAccessTokenRevocationRepository(),
    refreshTokenRepository: new MemoryRefreshTokenRepository(),
    signer,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0),
    userRepository: new MemoryUserRepository({ users })
  });

  return { app, auditRepository, material };
};

/** Form fields default to a valid agent exchange; pass null to omit a field. */
const requestAgentToken = ({
  app,
  basic,
  body = {}
}: {
  app: ReturnType<typeof createApp>;
  basic?: { clientId: string; secret: string };
  body?: Record<string, string | null>;
}) => {
  const fields: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT,
    subject_token_type: AGENT_ID_TOKEN_TYPE,
    subject_token: "agent_1",
    task_id: "task-42"
  };

  for (const [key, value] of Object.entries(body)) {
    if (value === null) {
      delete fields[key];
    } else {
      fields[key] = value;
    }
  }

  const headers = new Headers({
    "content-type": "application/x-www-form-urlencoded"
  });

  if (basic !== undefined) {
    headers.set("authorization", `Basic ${btoa(`${basic.clientId}:${basic.secret}`)}`);
  }

  return app.request(TOKEN_URL, {
    method: "POST",
    headers,
    body: new URLSearchParams(fields).toString()
  });
};

const verifyAccessToken = async (material: SigningKeyMaterial, token: string) => {
  const publicKey = await importJWK(material.key.publicJwk as JWK, "RS256");
  const verification = await jwtVerify(token, publicKey, { issuer: ISSUER });

  return verification.payload as Record<string, unknown>;
};

const runnerBasic = { clientId: "company_runner", secret: "runner-secret" };

describe("agent token exchange", () => {
  it("issues a task-bound token with the agent as subject and the claim source's fixed claims", async () => {
    const source = await createClient({
      clientId: "company_agent_claims",
      authMethod: "none",
      secret: null,
      grantTypes: []
    });
    const caller = await createClient({ agentClaimSourceClientId: source.clientId });
    const { app, material } = await createTestApp({
      clients: [caller, source],
      claims: [
        makeClaim({ clientId: source.id, claimName: "ac", fixedValue: "agent" }),
        makeClaim({ id: "claim_ns", clientId: source.id, claimName: "ns", fixedValue: "company" }),
        makeClaim({ id: "claim_db", clientId: source.id, claimName: "db", fixedValue: "main" }),
        makeClaim({
          id: "claim_rl",
          clientId: source.id,
          claimName: "rl",
          fixedValue: '["Editor"]',
          valueType: "json"
        })
      ],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({ app, basic: runnerBasic });

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(900);
    expect(body.refresh_token).toBeUndefined();
    expect(body.id_token).toBeUndefined();

    const payload = await verifyAccessToken(material, body.access_token as string);
    expect(payload.sub).toBe("agent_1");
    expect(payload.task).toBe("task-42");
    expect(payload.act).toEqual({ sub: "company_runner" });
    expect(payload.client_id).toBe("company_runner");
    expect(payload.aud).toBe("https://api.acme.test");
    expect(payload.ac).toBe("agent");
    expect(payload.ns).toBe("company");
    expect(payload.db).toBe("main");
    expect(payload.rl).toEqual(["Editor"]);
    expect((payload.exp as number) - (payload.iat as number)).toBe(900);
  });

  it("honors a shorter ttl and caps a longer one at 900 seconds", async () => {
    const caller = await createClient();
    const { app, material } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const shortened = await requestAgentToken({ app, basic: runnerBasic, body: { ttl: "120" } });
    const shortenedBody = (await shortened.json()) as { access_token: string; expires_in: number };
    const shortenedPayload = await verifyAccessToken(material, shortenedBody.access_token);

    expect(shortenedBody.expires_in).toBe(120);
    expect((shortenedPayload.exp as number) - (shortenedPayload.iat as number)).toBe(120);

    const capped = await requestAgentToken({ app, basic: runnerBasic, body: { ttl: "99999" } });
    const cappedBody = (await capped.json()) as { access_token: string; expires_in: number };
    const cappedPayload = await verifyAccessToken(material, cappedBody.access_token);

    expect(cappedBody.expires_in).toBe(900);
    expect((cappedPayload.exp as number) - (cappedPayload.iat as number)).toBe(900);
  });

  it("carries only the base claims when the client has no claim source", async () => {
    const caller = await createClient({ accessTokenAudience: null });
    const { app, material } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({ app, basic: runnerBasic });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const payload = await verifyAccessToken(material, body.access_token);
    expect(payload.aud).toBe("company_runner");
    expect(payload.task).toBe("task-42");
    expect(payload.act).toEqual({ sub: "company_runner" });
    expect(payload.ac).toBeUndefined();
    expect(payload.ns).toBeUndefined();
    expect(payload.db).toBeUndefined();
  });

  it("accepts client_secret_post credentials in the request body", async () => {
    const caller = await createClient({ authMethod: "client_secret_post" });
    const { app, material } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({
      app,
      body: { client_id: "company_runner", client_secret: "runner-secret" }
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    const payload = await verifyAccessToken(material, body.access_token);
    expect(payload.sub).toBe("agent_1");
  });

  it("refuses human users, whether kind is explicit or left at the legacy default", async () => {
    const caller = await createClient();
    const legacyHuman = makeUser({ id: "human_legacy" });
    delete legacyHuman.kind;
    const { app, auditRepository } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "human_explicit", kind: "human" }), legacyHuman]
    });

    for (const subject of ["human_explicit", "human_legacy"]) {
      const response = await requestAgentToken({
        app,
        basic: runnerBasic,
        body: { subject_token: subject }
      });

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_grant" });
    }

    const failed = auditRepository
      .listEvents()
      .filter((event) => event.eventType === "oidc.agent_token.exchange.failed");
    expect(failed).toHaveLength(2);
    expect(failed[0]?.payload).toEqual({ reason: "invalid_grant", task_id: "task-42" });
  });

  it("refuses agents that are disabled, provisioned, expired, cross-tenant, or unknown with invalid_grant", async () => {
    const caller = await createClient();
    const { app } = await createTestApp({
      clients: [caller],
      users: [
        makeUser({ id: "agent_disabled", status: "disabled" }),
        makeUser({ id: "agent_provisioned", status: "provisioned" }),
        makeUser({ id: "agent_expired", expiresAt: "2020-01-01T00:00:00Z" }),
        makeUser({ id: "agent_other", tenantId: "tenant_other" })
      ]
    });

    for (const subject of [
      "agent_disabled",
      "agent_provisioned",
      "agent_expired",
      "agent_other",
      "no_such_agent"
    ]) {
      const response = await requestAgentToken({
        app,
        basic: runnerBasic,
        body: { subject_token: subject }
      });

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_grant" });
    }
  });

  it("refuses a client that has not been opted in with unauthorized_client and audits it", async () => {
    const caller = await createClient({ agentTokenExchangeEnabled: false });
    const { app, auditRepository } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({ app, basic: runnerBasic });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "unauthorized_client" });

    const failed = auditRepository
      .listEvents()
      .filter((event) => event.eventType === "oidc.agent_token.exchange.failed");
    expect(failed).toHaveLength(1);
    expect(failed[0]?.payload).toEqual({ reason: "unauthorized_client" });
  });

  it("requires a confidential client, the right secret, and the client's own tenant", async () => {
    const publicClient = await createClient({
      authMethod: "none",
      clientId: "public_agent",
      secret: null
    });
    const otherTenantClient = await createClient({
      clientId: "other_runner",
      tenantId: "tenant_other"
    });
    const caller = await createClient();
    const { app } = await createTestApp({
      clients: [publicClient, otherTenantClient, caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const publicResponse = await requestAgentToken({
      app,
      body: { client_id: "public_agent" }
    });
    expect(publicResponse.status).toBe(401);
    expect(await publicResponse.json()).toEqual({ error: "invalid_client" });

    const otherTenantResponse = await requestAgentToken({
      app,
      basic: { clientId: "other_runner", secret: "runner-secret" }
    });
    expect(otherTenantResponse.status).toBe(401);
    expect(await otherTenantResponse.json()).toEqual({ error: "invalid_client" });

    const wrongSecretResponse = await requestAgentToken({
      app,
      basic: { clientId: "company_runner", secret: "wrong-secret" }
    });
    expect(wrongSecretResponse.status).toBe(401);
    expect(wrongSecretResponse.headers.get("www-authenticate")).toContain(
      'error="invalid_client"'
    );

    const anonymousResponse = await requestAgentToken({ app });
    expect(anonymousResponse.status).toBe(401);
    expect(await anonymousResponse.json()).toEqual({ error: "invalid_client" });
  });

  it("requires a well-formed task_id and accepts the longest allowed one", async () => {
    const caller = await createClient();
    const { app } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    for (const taskId of [null, "", "has space", "bad!id", "x".repeat(129)]) {
      const response = await requestAgentToken({
        app,
        basic: runnerBasic,
        body: { task_id: taskId }
      });

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_request" });
    }

    const longest = await requestAgentToken({
      app,
      basic: runnerBasic,
      body: { task_id: "A-z_09".padEnd(128, "x") }
    });
    expect(longest.status).toBe(200);
  });

  it("rejects a ttl that is not a positive integer", async () => {
    const caller = await createClient();
    const { app } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    for (const ttl of ["abc", "0", "-5", "1.5", " 120"]) {
      const response = await requestAgentToken({ app, basic: runnerBasic, body: { ttl } });

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_request" });
    }
  });

  it("fails closed when the configured claim source is missing or lives in another tenant", async () => {
    const foreignSource = await createClient({
      clientId: "foreign_claims",
      tenantId: "tenant_other",
      authMethod: "none",
      secret: null,
      grantTypes: []
    });
    const missingSourceCaller = await createClient({
      agentClaimSourceClientId: "no_such_client",
      clientId: "runner_missing_source"
    });
    const foreignSourceCaller = await createClient({
      agentClaimSourceClientId: foreignSource.clientId,
      clientId: "runner_foreign_source"
    });
    const { app, auditRepository } = await createTestApp({
      clients: [missingSourceCaller, foreignSourceCaller, foreignSource],
      users: [makeUser({ id: "agent_1" })]
    });

    for (const clientId of ["runner_missing_source", "runner_foreign_source"]) {
      const response = await requestAgentToken({
        app,
        basic: { clientId, secret: "runner-secret" }
      });

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "server_error" });
    }

    const succeeded = auditRepository
      .listEvents()
      .filter((event) => event.eventType === "oidc.agent_token.exchange.succeeded");
    expect(succeeded).toHaveLength(0);
  });

  it("records success with the agent and task ids but never token material", async () => {
    const caller = await createClient();
    const { app, auditRepository } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({ app, basic: runnerBasic });
    const body = (await response.json()) as { access_token: string };

    const events = auditRepository.listEvents();
    const succeeded = events.filter(
      (event) => event.eventType === "oidc.agent_token.exchange.succeeded"
    );
    expect(succeeded).toHaveLength(1);
    expect(succeeded[0]?.actorId).toBe("company_runner");
    expect(succeeded[0]?.payload).toEqual({
      agent_user_id: "agent_1",
      task_id: "task-42",
      expires_in: 900
    });
    expect(JSON.stringify(succeeded[0]?.payload ?? {})).not.toContain(body.access_token);
    expect(events.some((event) => event.eventType === "oidc.token.exchange.succeeded")).toBe(
      false
    );
  });

  it("keeps other token-exchange subject types on the remote-grant path", async () => {
    const caller = await createClient();
    const { app, auditRepository } = await createTestApp({
      clients: [caller],
      users: [makeUser({ id: "agent_1" })]
    });

    const response = await requestAgentToken({
      app,
      basic: runnerBasic,
      body: { subject_token_type: REMOTE_GRANT_CODE_TOKEN_TYPE, subject_token: "unknown-code" }
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_grant" });

    const events = auditRepository.listEvents();
    expect(events.some((event) => event.eventType === "oidc.agent_token.exchange.failed")).toBe(
      false
    );
    expect(events.some((event) => event.eventType === "oidc.token.exchange.failed")).toBe(true);
  });
});
