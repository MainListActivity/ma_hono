import { describe, expect, it } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import type { Client } from "../../src/domain/clients/types";
import type { KeyRepository } from "../../src/domain/keys/repository";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import { sha256Base64Url } from "../../src/lib/hash";

const bootstrapHash = "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI";

const ALL_SCOPES = [
  "tenant.read",
  "tenant.write",
  "user.read",
  "user.provision",
  "user.write",
  "client.read",
  "client.write",
  "key.rotate"
];

const keyRotationRepository: KeyRepository = {
  async listActiveKeysForTenant() {
    return [];
  },
  async retireActiveKeysForTenant() {}
};

const keyRotationSigner: SigningKeySigner = {
  async loadActiveSigningKeyMaterial() {
    return null;
  },
  async ensureActiveSigningKeyMaterial(tenantId: string) {
    return {
      key: {
        id: "key_rotated",
        tenantId,
        kid: "kid_rotated",
        alg: "RS256",
        kty: "RSA",
        status: "active",
        publicJwk: { kty: "RSA", kid: "kid_rotated", alg: "RS256", use: "sig" }
      },
      privateJwk: { kty: "RSA", kid: "kid_rotated", alg: "RS256" }
    };
  }
};

const createFixture = () => {
  const adminRepository = new MemoryAdminRepository({
    adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
  });
  const auditRepository = new MemoryAuditRepository();
  const clientRepository = new MemoryClientRepository();
  const tenantRepository = new MemoryTenantRepository([
    {
      id: "tenant_ck",
      slug: "ck",
      displayName: "CK",
      status: "active",
      issuers: [
        {
          id: "issuer_ck",
          issuerType: "platform_path",
          issuerUrl: "https://idp.example.test/t/ck",
          domain: null,
          isPrimary: true,
          verificationStatus: "verified"
        }
      ]
    }
  ]);
  const app = createApp({
    accessTokenClaimsRepository: new MemoryAccessTokenClaimsRepository(),
    adminBootstrapPasswordHash: bootstrapHash,
    adminWhitelist: ["admin@example.test"],
    adminRepository,
    auditRepository,
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository,
    keyRepository: keyRotationRepository,
    managementApiToken: "mgmt-token-not-for-provision",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    signer: keyRotationSigner,
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, adminRepository, auditRepository, clientRepository, tenantRepository };
};

const loginAsAdmin = async (app: ReturnType<typeof createFixture>["app"]) => {
  const response = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { session_token: string };
  return body.session_token;
};

const mintPrincipal = async (
  app: ReturnType<typeof createFixture>["app"],
  sessionToken: string,
  scopes: string[]
) => {
  const response = await app.request("https://idp.example.test/admin/service-principals", {
    method: "POST",
    headers: {
      authorization: `Bearer ${sessionToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ label: "scope-check", scopes })
  });
  expect(response.status).toBe(201);
  return (await response.json()) as { id: string; token: string };
};

const adminRequest = (
  app: ReturnType<typeof createFixture>["app"],
  token: string,
  method: string,
  path: string,
  body?: unknown
) =>
  app.request(`https://idp.example.test${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" })
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });

const seedClient = async (clientRepository: MemoryClientRepository, clientId: string) => {
  const client: Client = {
    id: `record_${clientId}`,
    tenantId: "tenant_ck",
    clientId,
    clientName: clientId,
    applicationType: "web",
    grantTypes: ["client_credentials"],
    redirectUris: [],
    responseTypes: [],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: await sha256Base64Url("secret"),
    trustLevel: "first_party_trusted",
    consentPolicy: "skip",
    clientProfile: "web",
    accessTokenAudience: null,
    agentTokenExchangeEnabled: false,
    agentClaimSourceClientId: null
  };
  await clientRepository.create(client);
};

const newClientBody = {
  client_name: "Company runner",
  client_profile: "web",
  application_type: "web",
  token_endpoint_auth_method: "client_secret_basic",
  grant_types: ["client_credentials"],
  redirect_uris: [],
  response_types: []
};

describe("service principal scopes for tenant, client and key routes", () => {
  it("lets tenant.write create and patch tenants and audits both as service_principal", async () => {
    const { app, auditRepository, tenantRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const writer = await mintPrincipal(app, sessionToken, ["tenant.write"]);

    const created = await adminRequest(app, writer.token, "POST", "/admin/tenants", {
      display_name: "Globex",
      slug: "globex"
    });
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as { id: string; slug: string };
    expect(createdBody.slug).toBe("globex");

    const patched = await adminRequest(
      app,
      writer.token,
      "PATCH",
      `/admin/tenants/${createdBody.id}`,
      { display_name: "Globex Corp" }
    );
    expect(patched.status).toBe(200);
    await expect(patched.json()).resolves.toMatchObject({
      slug: "globex",
      display_name: "Globex Corp"
    });
    await expect(tenantRepository.findById(createdBody.id)).resolves.toMatchObject({
      displayName: "Globex Corp"
    });

    const events = auditRepository.listEvents();
    expect(events.find((event) => event.eventType === "tenant.created")).toMatchObject({
      actorType: "service_principal",
      actorId: writer.id,
      targetId: createdBody.id
    });
    expect(events.find((event) => event.eventType === "tenant.updated")).toMatchObject({
      actorType: "service_principal",
      actorId: writer.id,
      targetId: createdBody.id,
      payload: { display_name: "Globex Corp" }
    });
    expect(JSON.stringify(events)).not.toContain(writer.token);
  });

  it("returns 403 for tenant writes when the token only holds tenant.read", async () => {
    const { app, tenantRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const reader = await mintPrincipal(app, sessionToken, ["tenant.read"]);

    const created = await adminRequest(app, reader.token, "POST", "/admin/tenants", {
      display_name: "Other",
      slug: "other"
    });
    expect(created.status).toBe(403);

    const patched = await adminRequest(app, reader.token, "PATCH", "/admin/tenants/tenant_ck", {
      display_name: "Hacked"
    });
    expect(patched.status).toBe(403);
    await expect(tenantRepository.findById("tenant_ck")).resolves.toMatchObject({
      displayName: "CK"
    });
  });

  it("keeps tenant delete, tenant detail and service principal management human-only", async () => {
    const { app, tenantRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const everything = await mintPrincipal(app, sessionToken, ALL_SCOPES);

    const removed = await adminRequest(app, everything.token, "DELETE", "/admin/tenants/tenant_ck");
    expect(removed.status).toBe(403);
    await expect(tenantRepository.findById("tenant_ck")).resolves.not.toBeNull();

    const detail = await adminRequest(app, everything.token, "GET", "/admin/tenants/tenant_ck");
    expect(detail.status).toBe(403);

    const list = await adminRequest(app, everything.token, "GET", "/admin/service-principals");
    expect(list.status).toBe(403);

    const mint = await adminRequest(app, everything.token, "POST", "/admin/service-principals", {
      label: "minted-by-machine",
      scopes: ["tenant.read"]
    });
    expect(mint.status).toBe(403);

    const revoke = await adminRequest(
      app,
      everything.token,
      "POST",
      `/admin/service-principals/${everything.id}/revoke`
    );
    expect(revoke.status).toBe(403);
  });

  it("does not offer a tenant.delete scope when minting", async () => {
    const { app } = createFixture();
    const sessionToken = await loginAsAdmin(app);

    const response = await adminRequest(app, sessionToken, "POST", "/admin/service-principals", {
      label: "bad-scope",
      scopes: ["tenant.delete"]
    });
    expect(response.status).toBe(400);
  });

  it("lets client.read list and read clients but not create them", async () => {
    const { app, clientRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    await seedClient(clientRepository, "company-runner");
    const reader = await mintPrincipal(app, sessionToken, ["client.read"]);

    const list = await adminRequest(app, reader.token, "GET", "/admin/tenants/tenant_ck/clients");
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      clients: [{ client_id: "company-runner" }]
    });

    const detail = await adminRequest(
      app,
      reader.token,
      "GET",
      "/admin/tenants/tenant_ck/clients/company-runner"
    );
    expect(detail.status).toBe(200);
    await expect(detail.json()).resolves.toMatchObject({
      client_id: "company-runner",
      token_endpoint_auth_method: "client_secret_basic"
    });

    const create = await adminRequest(
      app,
      reader.token,
      "POST",
      "/admin/tenants/tenant_ck/clients",
      newClientBody
    );
    expect(create.status).toBe(403);
  });

  it("returns 403 for every client write route when the token lacks client.write", async () => {
    const { app, clientRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    await seedClient(clientRepository, "company-runner");
    const reader = await mintPrincipal(app, sessionToken, [
      "client.read",
      "tenant.read",
      "key.rotate"
    ]);

    const responses = [
      await adminRequest(app, reader.token, "POST", "/admin/tenants/tenant_ck/clients", newClientBody),
      await adminRequest(
        app,
        reader.token,
        "PATCH",
        "/admin/tenants/tenant_ck/clients/company-runner",
        { client_name: "Renamed" }
      ),
      await adminRequest(
        app,
        reader.token,
        "PATCH",
        "/admin/tenants/tenant_ck/clients/company-runner/auth-method-policy",
        { mfa_required: true }
      ),
      await adminRequest(
        app,
        reader.token,
        "POST",
        "/admin/tenants/tenant_ck/clients/company-runner/secret/reset"
      ),
      await adminRequest(app, reader.token, "DELETE", "/admin/tenants/tenant_ck/clients/company-runner")
    ];
    expect(responses.map((response) => response.status)).toEqual([403, 403, 403, 403, 403]);
    await expect(clientRepository.findByClientId("company-runner")).resolves.not.toBeNull();
  });

  it("lets client.write create, update, set policy, reset secret and delete clients, auditing each as service_principal", async () => {
    const { app, auditRepository, clientRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const writer = await mintPrincipal(app, sessionToken, ["client.write"]);

    const created = await adminRequest(
      app,
      writer.token,
      "POST",
      "/admin/tenants/tenant_ck/clients",
      newClientBody
    );
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as { client_id: string; client_secret: string };
    expect(createdBody.client_secret).toBeTypeOf("string");
    const clientPath = `/admin/tenants/tenant_ck/clients/${createdBody.client_id}`;

    const renamed = await adminRequest(app, writer.token, "PATCH", clientPath, {
      client_name: "Company runner v2"
    });
    expect(renamed.status).toBe(200);

    const policy = await adminRequest(app, writer.token, "PATCH", `${clientPath}/auth-method-policy`, {
      mfa_required: true
    });
    expect(policy.status).toBe(200);

    const reset = await adminRequest(app, writer.token, "POST", `${clientPath}/secret/reset`);
    expect(reset.status).toBe(200);
    const resetBody = (await reset.json()) as { client_secret: string };
    expect(resetBody.client_secret).not.toBe(createdBody.client_secret);

    const removed = await adminRequest(app, writer.token, "DELETE", clientPath);
    expect(removed.status).toBe(200);
    await expect(clientRepository.findByClientId(createdBody.client_id)).resolves.toBeNull();

    const events = auditRepository.listEvents();
    for (const eventType of [
      "oidc.client.registered",
      "oidc.client.updated",
      "oidc.client.auth_method_policy.updated",
      "oidc.client.secret.reset",
      "oidc.client.deleted"
    ]) {
      expect(events.find((event) => event.eventType === eventType)).toMatchObject({
        actorType: "service_principal",
        actorId: writer.id,
        tenantId: "tenant_ck"
      });
    }
    expect(JSON.stringify(events)).not.toContain(writer.token);
  });

  it("returns 403 on client writes after the principal is revoked", async () => {
    const { app, clientRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const writer = await mintPrincipal(app, sessionToken, ["client.write"]);

    const revoke = await adminRequest(
      app,
      sessionToken,
      "POST",
      `/admin/service-principals/${writer.id}/revoke`
    );
    expect(revoke.status).toBe(200);

    const response = await adminRequest(
      app,
      writer.token,
      "POST",
      "/admin/tenants/tenant_ck/clients",
      newClientBody
    );
    expect(response.status).toBe(403);
    await expect(clientRepository.listByTenantId("tenant_ck")).resolves.toHaveLength(0);
  });

  it("lets key.rotate rotate signing keys and audits it, while other scopes get 403", async () => {
    const { app, auditRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    const rotator = await mintPrincipal(app, sessionToken, ["key.rotate"]);
    const other = await mintPrincipal(app, sessionToken, [
      "tenant.write",
      "client.write",
      "user.write"
    ]);

    const denied = await adminRequest(app, other.token, "POST", "/admin/tenants/tenant_ck/keys/rotate");
    expect(denied.status).toBe(403);

    const rotated = await adminRequest(app, rotator.token, "POST", "/admin/tenants/tenant_ck/keys/rotate");
    expect(rotated.status).toBe(200);
    await expect(rotated.json()).resolves.toMatchObject({ kid: "kid_rotated", alg: "RS256" });

    expect(
      auditRepository.listEvents().find((event) => event.eventType === "signing_key.rotated")
    ).toMatchObject({
      actorType: "service_principal",
      actorId: rotator.id,
      tenantId: "tenant_ck"
    });
  });

  it("keeps human admin sessions working on the routes that moved to scopes", async () => {
    const { app, auditRepository, clientRepository } = createFixture();
    const sessionToken = await loginAsAdmin(app);
    await seedClient(clientRepository, "company-runner");

    const clients = await adminRequest(app, sessionToken, "GET", "/admin/tenants/tenant_ck/clients");
    expect(clients.status).toBe(200);

    const created = await adminRequest(
      app,
      sessionToken,
      "POST",
      "/admin/tenants/tenant_ck/clients",
      { ...newClientBody, client_name: "Human-made runner" }
    );
    expect(created.status).toBe(201);

    const tenant = await adminRequest(app, sessionToken, "PATCH", "/admin/tenants/tenant_ck", {
      display_name: "CK"
    });
    expect(tenant.status).toBe(200);

    const rotated = await adminRequest(app, sessionToken, "POST", "/admin/tenants/tenant_ck/keys/rotate");
    expect(rotated.status).toBe(200);

    expect(
      auditRepository.listEvents().find((event) => event.eventType === "oidc.client.registered")
    ).toMatchObject({ actorType: "admin_user", actorId: "admin_1" });
  });
});
