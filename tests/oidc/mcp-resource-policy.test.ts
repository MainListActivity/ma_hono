import { describe, expect, it } from "vitest";
import { Hono } from "hono";

import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryConsentChallengeRepository } from "../../src/adapters/db/memory/memory-consent-challenge-repository";
import { MemoryLoginChallengeRepository } from "../../src/adapters/db/memory/memory-login-challenge-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import type { Client } from "../../src/domain/clients/types";

const resource = "https://auth.example.test/ops";
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
  }
]);

const mcpClient: Client = {
  id: "client_record_mcp",
  tenantId: "tenant_acme",
  clientId: "mcp-client",
  clientName: "Codex",
  applicationType: "native",
  grantTypes: ["authorization_code"],
  redirectUris: ["http://127.0.0.1:43123/callback"],
  responseTypes: ["code"],
  tokenEndpointAuthMethod: "none",
  clientSecretHash: null,
  trustLevel: "third_party",
  consentPolicy: "require",
  clientProfile: "native",
  accessTokenAudience: resource,
  allowedScopes: ["content.read"],
  initiateLoginUri: null,
  claimHookUrl: null,
  claimHookAuthHeaderName: null,
  claimHookAuthHeaderValue: null
};

const createPolicyApp = (
  clientRepository = new MemoryClientRepository([mcpClient]),
  authorizationCodeRepository = new MemoryAuthorizationCodeRepository(),
  loginChallengeRepository = new MemoryLoginChallengeRepository(),
  consentChallengeRepository = new MemoryConsentChallengeRepository()
) =>
  new Hono().route("/api", createApp({
    authorizationCodeRepository,
    authorizeSessionResolver: () => ({ tenantId: "tenant_acme", userId: "user-1" }),
    clientRepository, consentChallengeRepository, loginChallengeRepository,
    adminBootstrapPasswordHash: "", adminWhitelist: [], managementApiToken: "management-secret",
    mcpResource: resource, oidcHost: "idp.example.test", authDomain: "auth.example.test", tenantRepository,
    totpRepository: new MemoryTotpRepository(), mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32)
  })).route("/", createApp({
    authorizationCodeRepository,
    authorizeSessionResolver: () => ({ tenantId: "tenant_acme", userId: "user-1" }),
    clientRepository,
    consentChallengeRepository,
    loginChallengeRepository,
    adminBootstrapPasswordHash: "",
    adminWhitelist: [],
    managementApiToken: "management-secret",
    mcpResource: resource,
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    tenantRepository,
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  }));

describe("MCP resource indicators", () => {
  it("binds authorize requests to the managed resource and client scope ceiling", async () => {
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createPolicyApp(
      new MemoryClientRepository([
        { ...mcpClient, trustLevel: "first_party_trusted", consentPolicy: "skip" }
      ]),
      authorizationCodeRepository
    );
    const response = await app.request(
      `https://idp.example.test/t/acme/authorize?client_id=mcp-client&redirect_uri=${encodeURIComponent(
        "http://127.0.0.1:43123/callback"
      )}&response_type=code&scope=${encodeURIComponent("openid content.read")}&resource=${encodeURIComponent(
        resource
      )}&state=state-1&code_challenge=challenge&code_challenge_method=S256`
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(location.searchParams.get("code")).toBeTypeOf("string");
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.resource).toBe(resource);
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.scope).toBe(
      "openid content.read"
    );
  });

  it("rejects a different audience, missing resource, or a scope expansion", async () => {
    const cases = [
      `resource=${encodeURIComponent("https://other.example.test/ops")}&scope=${encodeURIComponent(
        "openid content.read"
      )}`,
      `scope=${encodeURIComponent("openid content.read")}`,
      `resource=${encodeURIComponent(resource)}&scope=${encodeURIComponent(
        "openid content.publish"
      )}`
    ];

    for (const suffix of cases) {
      const app = createPolicyApp();
      const response = await app.request(
        `https://idp.example.test/t/acme/authorize?client_id=mcp-client&redirect_uri=${encodeURIComponent(
          "http://127.0.0.1:43123/callback"
        )}&response_type=code&${suffix}&state=state-1&code_challenge=challenge&code_challenge_method=S256`
      );

      expect(response.status).toBe(302);
      const location = new URL(response.headers.get("location") ?? "");
      expect(location.searchParams.get("error")).toBe("invalid_scope");
    }
  });

  it("shows an explicit consent page and issues a code only after approval", async () => {
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const consentChallengeRepository = new MemoryConsentChallengeRepository();
    const app = createPolicyApp(
      undefined,
      authorizationCodeRepository,
      new MemoryLoginChallengeRepository(),
      consentChallengeRepository
    );
    const authorizeResponse = await app.request(
      `https://idp.example.test/t/acme/authorize?client_id=mcp-client&redirect_uri=${encodeURIComponent(
        "http://127.0.0.1:43123/callback"
      )}&response_type=code&scope=${encodeURIComponent("openid content.read")}&resource=${encodeURIComponent(
        resource
      )}&state=state-consent&code_challenge=challenge&code_challenge_method=S256`
    );

    expect(authorizeResponse.status).toBe(302);
    const consentLocation = new URL(authorizeResponse.headers.get("location") ?? "");
    expect(consentLocation.origin).toBe("https://auth.example.test");
    expect(consentLocation.pathname).toBe("/api/consent/acme");
    const challengeToken = consentLocation.searchParams.get("consent_challenge");
    expect(challengeToken).toBeTypeOf("string");

    const consentPage = await app.request(consentLocation.toString());
    expect(consentPage.status).toBe(200);
    expect(await consentPage.text()).toContain("Codex");

    const approval = await app.request(consentLocation.toString(), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        consent_challenge: challengeToken ?? "",
        decision: "approve"
      }).toString()
    });

    expect(approval.status).toBe(302);
    const callback = new URL(approval.headers.get("location") ?? "");
    expect(callback.searchParams.get("code")).toBeTypeOf("string");
    expect(consentChallengeRepository.listChallenges()[0]?.consumedAt).not.toBeNull();
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.resource).toBe(resource);

    const replay = await app.request(consentLocation.toString(), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        consent_challenge: challengeToken ?? "",
        decision: "approve"
      }).toString()
    });
    expect(replay.status).toBe(400);
  });
});
