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
import type { Tenant } from "../../src/domain/tenants/types";
import { sha256Base64Url } from "../../src/lib/hash";

const acmeTenant: Tenant = {
  id: "tenant_acme",
  slug: "acme",
  displayName: "Acme Corp",
  status: "active",
  issuers: [
    {
      id: "issuer_1",
      issuerType: "platform_path",
      issuerUrl: "https://idp.example.test/t/acme",
      domain: null,
      isPrimary: true,
      verificationStatus: "verified"
    }
  ]
};

const makeApp = () => {
  const clientRepository = new MemoryClientRepository();
  const app = createApp({
    accessTokenClaimsRepository: new MemoryAccessTokenClaimsRepository(),
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminRepository: new MemoryAdminRepository({
      adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
    }),
    auditRepository: new MemoryAuditRepository(),
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository,
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository: new MemoryTenantRepository([acmeTenant]),
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, clientRepository };
};

const loginAsAdmin = async (app: ReturnType<typeof makeApp>["app"]) => {
  const response = await app.request("https://idp.example.test/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
  });
  const body = (await response.json()) as { session_token: string };
  return body.session_token;
};

const CLIENTS_URL = "https://idp.example.test/admin/tenants/tenant_acme/clients";

/** A confidential machine client, used as a runner or as a claim source. */
const seedMachineClient = async (
  clientRepository: MemoryClientRepository,
  {
    clientId,
    tenantId = "tenant_acme"
  }: { clientId: string; tenantId?: string }
) => {
  const client: Client = {
    id: `record_${clientId}`,
    tenantId,
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

/** An interactive native client; its auth method decides whether it can hold agent policy. */
const seedNativeClient = async (
  clientRepository: MemoryClientRepository,
  {
    agentTokenExchangeEnabled = false,
    clientId,
    tokenEndpointAuthMethod
  }: {
    agentTokenExchangeEnabled?: boolean;
    clientId: string;
    tokenEndpointAuthMethod: Client["tokenEndpointAuthMethod"];
  }
) => {
  const isPublic = tokenEndpointAuthMethod === "none";
  const client: Client = {
    id: `record_${clientId}`,
    tenantId: "tenant_acme",
    clientId,
    clientName: clientId,
    applicationType: "native",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.example.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod,
    clientSecretHash: isPublic ? null : await sha256Base64Url("secret"),
    trustLevel: "first_party_trusted",
    consentPolicy: "skip",
    clientProfile: "native",
    accessTokenAudience: null,
    agentTokenExchangeEnabled
  };
  await clientRepository.create(client);
};

const patchClient = (
  app: ReturnType<typeof makeApp>["app"],
  token: string,
  clientId: string,
  body: Record<string, unknown>
) =>
  app.request(`${CLIENTS_URL}/${clientId}`, {
    method: "PATCH",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });

const createClient = (
  app: ReturnType<typeof makeApp>["app"],
  token: string,
  body: Record<string, unknown>
) =>
  app.request(CLIENTS_URL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });

const machineRegistration = (body: Record<string, unknown>) => ({
  client_name: "Company agent runner",
  client_profile: "web",
  application_type: "web",
  token_endpoint_auth_method: "client_secret_basic",
  grant_types: ["client_credentials"],
  redirect_uris: [],
  response_types: [],
  ...body
});

const nativeRegistration = (body: Record<string, unknown>) => ({
  client_name: "Native agent host",
  client_profile: "native",
  application_type: "native",
  token_endpoint_auth_method: "none",
  grant_types: ["authorization_code"],
  redirect_uris: ["https://app.example.test/callback"],
  response_types: ["code"],
  ...body
});

describe("agent token exchange client policy (admin API)", () => {
  it("defaults the policy off and exposes it on the client detail", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, { clientId: "runner" });

    const response = await app.request(`${CLIENTS_URL}/runner`, {
      headers: { authorization: `Bearer ${token}` }
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      agent_token_exchange_enabled: false,
      agent_claim_source_client_id: null
    });
  });

  it("stores the policy and claim source at registration and echoes them back", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, { clientId: "agent-claims" });

    const response = await createClient(
      app,
      token,
      machineRegistration({
        agent_token_exchange_enabled: true,
        agent_claim_source_client_id: "agent-claims"
      })
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      agent_claim_source_client_id: string;
      agent_token_exchange_enabled: boolean;
      client_id: string;
    };
    expect(body).toMatchObject({
      agent_token_exchange_enabled: true,
      agent_claim_source_client_id: "agent-claims"
    });

    const stored = await clientRepository.findByClientId(body.client_id);
    expect(stored?.agentTokenExchangeEnabled).toBe(true);
    expect(stored?.agentClaimSourceClientId).toBe("agent-claims");
  });

  it("rejects agent token exchange on a public registration", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);

    const response = await createClient(
      app,
      token,
      nativeRegistration({ agent_token_exchange_enabled: true })
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: string; issues: { message: string }[] };
    expect(body.error).toBe("invalid_client_metadata");
    expect(body.issues.map((issue) => issue.message)).toContain(
      "agent token exchange requires a confidential token_endpoint_auth_method"
    );
    expect(await clientRepository.listByTenantId("tenant_acme")).toHaveLength(0);
  });

  it("rejects a claim source that is missing or belongs to another tenant", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, {
      clientId: "foreign-claims",
      tenantId: "tenant_other"
    });

    for (const claimSource of ["no-such-client", "foreign-claims"]) {
      const response = await createClient(
        app,
        token,
        machineRegistration({
          agent_token_exchange_enabled: true,
          agent_claim_source_client_id: claimSource
        })
      );

      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toEqual({
        error: "invalid_client_metadata",
        message: "agent_claim_source_client_id must reference a client in this tenant"
      });
    }

    expect(await clientRepository.listByTenantId("tenant_acme")).toHaveLength(0);
  });

  it("rejects a policy flag that is not a boolean", async () => {
    const { app } = makeApp();
    const token = await loginAsAdmin(app);

    const response = await createClient(
      app,
      token,
      machineRegistration({ agent_token_exchange_enabled: "yes" })
    );

    expect(response.status).toBe(400);
  });

  it("turns the policy on for a confidential client on update", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, { clientId: "runner" });
    await seedMachineClient(clientRepository, { clientId: "agent-claims" });

    const response = await patchClient(app, token, "runner", {
      agent_token_exchange_enabled: true,
      agent_claim_source_client_id: "agent-claims"
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      agent_token_exchange_enabled: true,
      agent_claim_source_client_id: "agent-claims"
    });
    await expect(clientRepository.findByClientId("runner")).resolves.toMatchObject({
      agentTokenExchangeEnabled: true,
      agentClaimSourceClientId: "agent-claims"
    });
  });

  it("clears the claim source when null is sent on update", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, { clientId: "runner" });
    await seedMachineClient(clientRepository, { clientId: "agent-claims" });
    await patchClient(app, token, "runner", {
      agent_token_exchange_enabled: true,
      agent_claim_source_client_id: "agent-claims"
    });

    const response = await patchClient(app, token, "runner", {
      agent_claim_source_client_id: null
    });

    expect(response.status).toBe(200);
    await expect(clientRepository.findByClientId("runner")).resolves.toMatchObject({
      agentTokenExchangeEnabled: true,
      agentClaimSourceClientId: null
    });
  });

  it("refuses to turn the policy on for a public client", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedNativeClient(clientRepository, {
      clientId: "public-native",
      tokenEndpointAuthMethod: "none"
    });

    const response = await patchClient(app, token, "public-native", {
      agent_token_exchange_enabled: true
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_client_metadata",
      message: "agent token exchange requires a confidential auth method"
    });
    await expect(clientRepository.findByClientId("public-native")).resolves.toMatchObject({
      agentTokenExchangeEnabled: false
    });
  });

  it("refuses to make an opted-in client public (checked on the merged state)", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedNativeClient(clientRepository, {
      agentTokenExchangeEnabled: true,
      clientId: "native-runner",
      tokenEndpointAuthMethod: "client_secret_basic"
    });

    const response = await patchClient(app, token, "native-runner", {
      token_endpoint_auth_method: "none"
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_client_metadata",
      message: "agent token exchange requires a confidential auth method"
    });
    await expect(clientRepository.findByClientId("native-runner")).resolves.toMatchObject({
      tokenEndpointAuthMethod: "client_secret_basic",
      agentTokenExchangeEnabled: true
    });
  });

  it("rejects a claim source that belongs to another tenant on update", async () => {
    const { app, clientRepository } = makeApp();
    const token = await loginAsAdmin(app);
    await seedMachineClient(clientRepository, { clientId: "runner" });
    await seedMachineClient(clientRepository, {
      clientId: "foreign-claims",
      tenantId: "tenant_other"
    });

    const response = await patchClient(app, token, "runner", {
      agent_claim_source_client_id: "foreign-claims"
    });

    expect(response.status).toBe(400);
    await expect(clientRepository.findByClientId("runner")).resolves.toMatchObject({
      agentClaimSourceClientId: null
    });
  });
});
