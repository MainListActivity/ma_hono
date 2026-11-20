import { describe, expect, it } from "vitest";

import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryConsentChallengeRepository } from "../../src/adapters/db/memory/memory-consent-challenge-repository";
import { MemoryLoginChallengeRepository } from "../../src/adapters/db/memory/memory-login-challenge-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryRegistrationAccessTokenRepository } from "../../src/adapters/db/memory/memory-registration-access-token-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import type { Client } from "../../src/domain/clients/types";

const globalResource = "https://l.example.test/api/ops/mcp";
const companyResource = "https://company.example.test/api/mcp";

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
        issuerUrl: "https://idp.example.test/t/acme",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  },
  {
    id: "tenant_company",
    slug: "company",
    displayName: "Company",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_company",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/company",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  }
]);

const createTenantMcpApp = (
  clientRepository = new MemoryClientRepository(),
  authorizationCodeRepository = new MemoryAuthorizationCodeRepository()
) =>
  createApp({
    authorizationCodeRepository,
    authorizeSessionResolver: (context) =>
      new URL(context.req.url).pathname.startsWith("/t/company")
        ? { tenantId: "tenant_company", userId: "user-company" }
        : { tenantId: "tenant_acme", userId: "user-1" },
    clientRepository,
    consentChallengeRepository: new MemoryConsentChallengeRepository(),
    loginChallengeRepository: new MemoryLoginChallengeRepository(),
    registrationAccessTokenRepository: new MemoryRegistrationAccessTokenRepository(),
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "management-secret",
    mcpResource: globalResource,
    mcpResourcesByTenant: {
      company: { resource: companyResource, scopes: ["company.work"] }
    },
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

describe("按租户配置 MCP 资源", () => {
  it("company 租户 discovery 公布公司资源与 company.work，不泄露全局 scope", async () => {
    const app = createTenantMcpApp();
    const response = await app.request(
      "https://idp.example.test/t/company/.well-known/openid-configuration"
    );

    expect(response.status).toBe(200);
    const metadata = (await response.json()) as {
      mcp_resource: string;
      scopes_supported: string[];
    };

    expect(metadata.mcp_resource).toBe(companyResource);
    expect(metadata.scopes_supported).toContain("openid");
    expect(metadata.scopes_supported).toContain("company.work");
    expect(metadata.scopes_supported).not.toContain("content.read");
    expect(metadata.scopes_supported).not.toContain("content.submit");
  });

  it("未登记租户 discovery 仍公布全局资源（今天的行为）", async () => {
    const app = createTenantMcpApp();
    const response = await app.request(
      "https://idp.example.test/t/acme/.well-known/openid-configuration"
    );

    expect(response.status).toBe(200);
    const metadata = (await response.json()) as {
      mcp_resource: string;
      scopes_supported: string[];
    };

    expect(metadata.mcp_resource).toBe(globalResource);
    expect(metadata.scopes_supported).toContain("openid");
    expect(metadata.scopes_supported).toContain("content.read");
    expect(metadata.scopes_supported).not.toContain("company.work");
  });

  it("company 租户 DCR 注册绑定公司资源与 audience", async () => {
    const clientRepository = new MemoryClientRepository();
    const app = createTenantMcpApp(clientRepository);

    const response = await app.request("https://idp.example.test/t/company/connect/mcp/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Company connector",
        application_type: "native",
        redirect_uris: ["http://127.0.0.1:43123/callback"],
        token_endpoint_auth_method: "none",
        resource: companyResource,
        scope: "openid company.work"
      })
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as { client_id: string; resource: string; scope: string };
    const stored = await clientRepository.findByClientId(body.client_id);

    expect(body.resource).toBe(companyResource);
    expect(body.scope).toBe("openid company.work");
    expect(stored?.accessTokenAudience).toBe(companyResource);
    expect(stored?.allowedScopes).toEqual(["company.work"]);
  });

  it("company 租户请求全局资源或全局 scope 被拒", async () => {
    const app = createTenantMcpApp();

    const wrongResource = await app.request("https://idp.example.test/t/company/connect/mcp/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Wrong resource",
        redirect_uris: ["https://connectors.example.test/oauth/callback"],
        resource: globalResource,
        scope: "openid company.work"
      })
    });
    expect(wrongResource.status).toBe(400);

    const wrongScope = await app.request("https://idp.example.test/t/company/connect/mcp/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Wrong scope",
        redirect_uris: ["https://connectors.example.test/oauth/callback"],
        resource: companyResource,
        scope: "openid content.read"
      })
    });
    expect(wrongScope.status).toBe(400);
  });

  it("acme 租户请求公司资源被拒", async () => {
    const app = createTenantMcpApp();

    const response = await app.request("https://idp.example.test/t/acme/connect/mcp/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Cross tenant",
        redirect_uris: ["https://connectors.example.test/oauth/callback"],
        resource: companyResource,
        scope: "openid company.work"
      })
    });

    expect(response.status).toBe(400);
  });

  it("company 租户 authorize 带公司资源与 company.work 通过", async () => {
    const companyClient: Client = {
      id: "client_record_company",
      tenantId: "tenant_company",
      clientId: "company-mcp-client",
      clientName: "Company MCP",
      applicationType: "native",
      grantTypes: ["authorization_code"],
      redirectUris: ["http://127.0.0.1:43123/callback"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      clientProfile: "native",
      accessTokenAudience: companyResource,
      allowedScopes: ["company.work"],
      initiateLoginUri: null,
      claimHookUrl: null,
      claimHookAuthHeaderName: null,
      claimHookAuthHeaderValue: null
    };
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createTenantMcpApp(
      new MemoryClientRepository([companyClient]),
      authorizationCodeRepository
    );

    const response = await app.request(
      `https://idp.example.test/t/company/authorize?client_id=company-mcp-client&redirect_uri=${encodeURIComponent(
        "http://127.0.0.1:43123/callback"
      )}&response_type=code&scope=${encodeURIComponent("openid company.work")}&resource=${encodeURIComponent(
        companyResource
      )}&state=state-1&code_challenge=challenge&code_challenge_method=S256`
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.searchParams.get("code")).toBeTypeOf("string");
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.resource).toBe(companyResource);
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.scope).toBe(
      "openid company.work"
    );
  });

  it("acme 租户 authorize 请求公司资源被拒，全局资源仍按原策略通过", async () => {
    const acmeClient: Client = {
      id: "client_record_acme",
      tenantId: "tenant_acme",
      clientId: "acme-mcp-client",
      clientName: "Acme MCP",
      applicationType: "native",
      grantTypes: ["authorization_code"],
      redirectUris: ["http://127.0.0.1:43123/callback"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      clientSecretHash: null,
      trustLevel: "first_party_trusted",
      consentPolicy: "skip",
      clientProfile: "native",
      accessTokenAudience: globalResource,
      allowedScopes: ["content.read"],
      initiateLoginUri: null,
      claimHookUrl: null,
      claimHookAuthHeaderName: null,
      claimHookAuthHeaderValue: null
    };
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createTenantMcpApp(
      new MemoryClientRepository([acmeClient]),
      authorizationCodeRepository
    );

    const base =
      "client_id=acme-mcp-client&redirect_uri=" +
      encodeURIComponent("http://127.0.0.1:43123/callback") +
      "&response_type=code&state=state-1&code_challenge=challenge&code_challenge_method=S256";

    const rejected = await app.request(
      `https://idp.example.test/t/acme/authorize?${base}&scope=${encodeURIComponent(
        "openid company.work"
      )}&resource=${encodeURIComponent(companyResource)}`
    );
    expect(rejected.status).toBe(302);
    const rejectedLocation = new URL(rejected.headers.get("location") ?? "");
    expect(rejectedLocation.searchParams.get("error")).toBeTypeOf("string");
    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(0);

    const accepted = await app.request(
      `https://idp.example.test/t/acme/authorize?${base}&scope=${encodeURIComponent(
        "openid content.read"
      )}&resource=${encodeURIComponent(globalResource)}`
    );
    expect(accepted.status).toBe(302);
    const acceptedLocation = new URL(accepted.headers.get("location") ?? "");
    expect(acceptedLocation.searchParams.get("code")).toBeTypeOf("string");
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.resource).toBe(globalResource);
  });
});
