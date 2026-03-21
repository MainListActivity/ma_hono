import { describe, expect, it, vi } from "vitest";

import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryLoginChallengeRepository } from "../../src/adapters/db/memory/memory-login-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { createApp } from "../../src/app/app";
import { dynamicClientRegistrationSchema } from "../../src/domain/clients/registration-schema";
import type { Client } from "../../src/domain/clients/types";
import { sha256Base64Url } from "../../src/lib/hash";

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
      },
      {
        id: "issuer_custom_acme",
        issuerType: "custom_domain",
        issuerUrl: "https://login.acme.test",
        domain: "login.acme.test",
        isPrimary: false,
        verificationStatus: "verified"
      }
    ]
  },
  {
    id: "tenant_disabled",
    slug: "disabled",
    displayName: "Disabled",
    status: "disabled",
    issuers: [
      {
        id: "issuer_platform_disabled",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/disabled",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  },
  {
    id: "tenant_beta",
    slug: "beta",
    displayName: "Beta",
    status: "active",
    issuers: [
      {
        id: "issuer_platform_beta",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/beta",
        domain: null,
        isPrimary: true,
        verificationStatus: "verified"
      }
    ]
  }
]);

const clients: Client[] = [
  {
    id: "client_record_acme_first_party",
    tenantId: "tenant_acme",
    clientId: "client_acme_first_party",
    clientName: "Acme Web",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  },
  {
    id: "client_record_acme_consent_review",
    tenantId: "tenant_acme",
    clientId: "client_acme_consent_review",
    clientName: "Acme Consent Review",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://review.acme.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "require"
  },
  {
    id: "client_record_acme_no_code_grant",
    tenantId: "tenant_acme",
    clientId: "client_acme_no_code_grant",
    clientName: "Acme No Code Grant",
    applicationType: "web",
    grantTypes: ["client_credentials"],
    redirectUris: ["https://app.acme.test/no-code"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  },
  {
    id: "client_record_acme_no_code_response",
    tenantId: "tenant_acme",
    clientId: "client_acme_no_code_response",
    clientName: "Acme No Code Response",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.acme.test/no-response"],
    responseTypes: ["token"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  },
  {
    id: "client_record_beta",
    tenantId: "tenant_beta",
    clientId: "client_beta",
    clientName: "Beta Web",
    applicationType: "web",
    grantTypes: ["authorization_code"],
    redirectUris: ["https://app.beta.test/callback"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "client_secret_basic",
    clientSecretHash: "hashed-secret",
    trustLevel: "first_party_trusted",
    consentPolicy: "skip"
  }
];

const authorizeQuery =
  "client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=code&scope=openid%20profile&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256";

describe("/authorize", () => {
  it("creates a login challenge and redirects an unauthenticated platform-path request to login", async () => {
    const loginChallengeRepository = new MemoryLoginChallengeRepository();
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository,
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      `https://idp.example.test/t/acme/authorize?${authorizeQuery}`
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toMatch(
      /^https:\/\/idp\.example\.test\/t\/acme\/login\?login_challenge=/
    );

    const location = new URL(response.headers.get("location") ?? "");
    const loginChallengeToken = location.searchParams.get("login_challenge");

    expect(loginChallengeToken).not.toBeNull();
    expect(loginChallengeRepository.listChallenges()).toHaveLength(1);
    expect(loginChallengeRepository.listChallenges()[0]).toMatchObject({
      issuer: "https://idp.example.test/t/acme",
      tenantId: "tenant_acme",
      clientId: "client_acme_first_party",
      redirectUri: "https://app.acme.test/callback",
      scope: "openid profile",
      state: "opaque-state",
      codeChallenge: "pkce-challenge",
      codeChallengeMethod: "S256",
      nonce: null
    });
    expect(loginChallengeRepository.listChallenges()[0]?.tokenHash).toBe(
      await sha256Base64Url(loginChallengeToken ?? "")
    );
    expect(auditRepository.listEvents()).toEqual([]);

    const loginEntryResponse = await app.request(location.toString());

    expect(loginEntryResponse.status).toBe(501);
    expect(await loginEntryResponse.json()).toEqual({
      error: "login_not_implemented",
      issuer: "https://idp.example.test/t/acme",
      login_challenge: loginChallengeToken
    });
  });

  it("uses the resolved custom-domain issuer when creating a login challenge", async () => {
    const loginChallengeRepository = new MemoryLoginChallengeRepository();
    const app = createApp({
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository,
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      `https://login.acme.test/authorize?${authorizeQuery}`
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");

    expect(location).toMatch(
      /^https:\/\/login\.acme\.test\/login\?login_challenge=/
    );
    expect(loginChallengeRepository.listChallenges()[0]?.issuer).toBe("https://login.acme.test");

    const loginEntryResponse = await app.request(location ?? "");

    expect(loginEntryResponse.status).toBe(501);
    expect(await loginEntryResponse.json()).toEqual({
      error: "login_not_implemented",
      issuer: "https://login.acme.test",
      login_challenge: new URL(location ?? "").searchParams.get("login_challenge")
    });
  });

  it("rejects authorization for a disabled tenant issuer", async () => {
    const app = createApp({
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/disabled/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(response.status).toBe(404);
  });

  it("rejects a client that does not belong to the resolved tenant and audits the failure", async () => {
    const auditRepository = new MemoryAuditRepository();
    const app = createApp({
      auditRepository,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_beta&redirect_uri=https%3A%2F%2Fapp.beta.test%2Fcallback&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_client" });
    expect(auditRepository.listEvents()).toHaveLength(1);
    expect(auditRepository.listEvents()[0]).toMatchObject({
      tenantId: "tenant_acme",
      eventType: "oidc.authorization.failed",
      payload: {
        client_id: "client_beta",
        reason: "invalid_client"
      }
    });
  });

  it("requires an exact redirect uri match", async () => {
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback%2Fextra&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_redirect_uri" });
  });

  it("redirects validated-request authorization errors back to the client", async () => {
    const app = createApp({
      auditRepository: new MemoryAuditRepository(),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const unsupportedResponseType = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=token&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(unsupportedResponseType.status).toBe(302);
    const unsupportedResponseTypeLocation = new URL(
      unsupportedResponseType.headers.get("location") ?? ""
    );

    expect(unsupportedResponseTypeLocation.origin + unsupportedResponseTypeLocation.pathname).toBe(
      "https://app.acme.test/callback"
    );
    expect(unsupportedResponseTypeLocation.searchParams.get("error")).toBe(
      "unsupported_response_type"
    );
    expect(unsupportedResponseTypeLocation.searchParams.get("state")).toBe("opaque-state");

    const missingOpenIdScope = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=code&scope=profile&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(missingOpenIdScope.status).toBe(302);
    const missingOpenIdScopeLocation = new URL(missingOpenIdScope.headers.get("location") ?? "");

    expect(missingOpenIdScopeLocation.searchParams.get("error")).toBe("invalid_scope");
    expect(missingOpenIdScopeLocation.searchParams.get("error_description")).toBe(
      "scope must include openid"
    );
    expect(missingOpenIdScopeLocation.searchParams.get("state")).toBe("opaque-state");

    const missingAuthorizationCodeGrant = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_no_code_grant&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fno-code&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(missingAuthorizationCodeGrant.status).toBe(302);
    const missingAuthorizationCodeGrantLocation = new URL(
      missingAuthorizationCodeGrant.headers.get("location") ?? ""
    );

    expect(
      missingAuthorizationCodeGrantLocation.origin + missingAuthorizationCodeGrantLocation.pathname
    ).toBe("https://app.acme.test/no-code");
    expect(missingAuthorizationCodeGrantLocation.searchParams.get("error")).toBe(
      "unauthorized_client"
    );
    expect(missingAuthorizationCodeGrantLocation.searchParams.get("state")).toBe("opaque-state");

    const missingCodeResponseType = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_no_code_response&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fno-response&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(missingCodeResponseType.status).toBe(302);
    const missingCodeResponseTypeLocation = new URL(
      missingCodeResponseType.headers.get("location") ?? ""
    );

    expect(missingCodeResponseTypeLocation.searchParams.get("error")).toBe(
      "unauthorized_client"
    );
    expect(missingCodeResponseTypeLocation.searchParams.get("state")).toBe("opaque-state");

    const missingPkce = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=code&scope=openid&state=opaque-state"
    );

    expect(missingPkce.status).toBe(302);
    const missingPkceLocation = new URL(missingPkce.headers.get("location") ?? "");

    expect(missingPkceLocation.searchParams.get("error")).toBe("invalid_request");
    expect(missingPkceLocation.searchParams.get("error_description")).toBe("PKCE is required");
    expect(missingPkceLocation.searchParams.get("state")).toBe("opaque-state");
  });

  it("auto-continues only trusted first-party clients with skip consent and persists the authorization code", async () => {
    const auditRepository = new MemoryAuditRepository();
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository,
      authorizeSessionResolver: async (context) =>
        context.req.header("x-user-id") === "user_123" ? { userId: "user_123" } : null,
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      `https://idp.example.test/t/acme/authorize?${authorizeQuery}`,
      {
        headers: {
          "x-user-id": "user_123"
        }
      }
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");

    expect(location.origin + location.pathname).toBe("https://app.acme.test/callback");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("opaque-state");

    const authorizationCode = authorizationCodeRepository.listAuthorizationCodes()[0];

    expect(authorizationCodeRepository.listAuthorizationCodes()).toHaveLength(1);
    expect(authorizationCode).toMatchObject({
      issuer: "https://idp.example.test/t/acme",
      tenantId: "tenant_acme",
      clientId: "client_acme_first_party",
      userId: "user_123",
      redirectUri: "https://app.acme.test/callback",
      codeChallenge: "pkce-challenge",
      codeChallengeMethod: "S256",
      scope: "openid profile",
      nonce: null
    });
    expect(authorizationCode?.tokenHash).toBe(
      await sha256Base64Url(location.searchParams.get("code") ?? "")
    );
    expect(auditRepository.listEvents()).toHaveLength(1);
    expect(auditRepository.listEvents()[0]).toMatchObject({
      tenantId: "tenant_acme",
      eventType: "oidc.authorization.succeeded",
      targetType: "oidc_client",
      targetId: "client_acme_first_party",
      payload: {
        user_id: "user_123"
      }
    });
  });

  it("audits and defers when the client requires consent review", async () => {
    const auditRepository = new MemoryAuditRepository();
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createApp({
      auditRepository,
      authorizationCodeRepository,
      authorizeSessionResolver: async () => ({ userId: "user_123" }),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_consent_review&redirect_uri=https%3A%2F%2Freview.acme.test%2Fcallback&response_type=code&scope=openid&state=opaque-state&code_challenge=pkce-challenge&code_challenge_method=S256"
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");

    expect(location.origin + location.pathname).toBe("https://review.acme.test/callback");
    expect(location.searchParams.get("error")).toBe("consent_required");
    expect(location.searchParams.get("state")).toBe("opaque-state");
    expect(authorizationCodeRepository.listAuthorizationCodes()).toEqual([]);
    expect(auditRepository.listEvents()).toHaveLength(1);
    expect(auditRepository.listEvents()[0]).toMatchObject({
      tenantId: "tenant_acme",
      eventType: "oidc.authorization.deferred",
      targetId: "client_acme_consent_review",
      payload: {
        reason: "consent_required"
      }
    });
  });

  it("preserves a provided nonce in the authorization code", async () => {
    const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
    const app = createApp({
      authorizationCodeRepository,
      authorizeSessionResolver: async () => ({ userId: "user_123" }),
      clientRepository: new MemoryClientRepository(clients),
      loginChallengeRepository: new MemoryLoginChallengeRepository(),
      platformHost: "idp.example.test",
      tenantRepository
    });

    const response = await app.request(
      "https://idp.example.test/t/acme/authorize?client_id=client_acme_first_party&redirect_uri=https%3A%2F%2Fapp.acme.test%2Fcallback&response_type=code&scope=openid%20profile&state=opaque-state&nonce=nonce-123&code_challenge=pkce-challenge&code_challenge_method=S256",
      {
        headers: {
          "x-user-id": "user_123"
        }
      }
    );

    expect(response.status).toBe(302);
    expect(authorizationCodeRepository.listAuthorizationCodes()[0]?.nonce).toBe("nonce-123");
  });
});

describe("dynamicClientRegistrationSchema", () => {
  it("defaults v1 clients to trusted first-party skip-consent semantics", () => {
    const result = dynamicClientRegistrationSchema.parse({
      client_name: "Acme Web",
      application_type: "web",
      grant_types: ["authorization_code"],
      redirect_uris: ["https://app.acme.test/callback"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic"
    });

    expect(result.trust_level).toBe("first_party_trusted");
    expect(result.consent_policy).toBe("skip");
  });

  it("rejects non-v1 trust or consent settings", () => {
    expect(() =>
      dynamicClientRegistrationSchema.parse({
        client_name: "Acme Web",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["code"],
        trust_level: "third_party",
        token_endpoint_auth_method: "client_secret_basic"
      })
    ).toThrow();

    expect(() =>
      dynamicClientRegistrationSchema.parse({
        client_name: "Acme Web",
        application_type: "web",
        grant_types: ["authorization_code"],
        redirect_uris: ["https://app.acme.test/callback"],
        response_types: ["code"],
        consent_policy: "require",
        token_endpoint_auth_method: "client_secret_basic"
      })
    ).toThrow();
  });
});

describe("worker entrypoint wiring", () => {
  it("injects D1-backed authorize repositories into createApp", async () => {
    vi.resetModules();

    const authorizationCodeRepository = {
      create: vi.fn()
    };
    const loginChallengeRepository = {
      create: vi.fn()
    };
    const close = vi.fn(async () => undefined);
    const appFetch = vi.fn(async () => new Response(null, { status: 204 }));
    const createApp = vi.fn(() => ({
      fetch: appFetch
    }));
    const createRuntimeRepositories = vi.fn(async () => ({
      adminRepository: {},
      auditRepository: {},
      authorizationCodeRepository,
      clientRepository: {},
      close,
      keyRepository: {},
      loginChallengeRepository,
      registrationAccessTokenRepository: {},
      tenantRepository: {}
    }));
    const readRuntimeConfig = vi.fn(() => ({
      adminBootstrapPassword: "bootstrap",
      adminWhitelist: [],
      managementApiToken: "manage-token",
      platformHost: "idp.example.test"
    }));

    vi.doMock("../../src/app/app", () => ({
      createApp
    }));
    vi.doMock("../../src/adapters/db/drizzle/runtime", () => ({
      createRuntimeRepositories
    }));
    vi.doMock("../../src/config/env", () => ({
      readRuntimeConfig
    }));

    try {
      const worker = (await import("../../src/index")).default;

      await worker.fetch(
        new Request("https://idp.example.test/t/acme/authorize"),
        {} as Record<string, unknown>,
        {} as ExecutionContext
      );

      expect(createApp).toHaveBeenCalledWith(
        expect.objectContaining({
          authorizationCodeRepository,
          loginChallengeRepository
        })
      );
      expect(appFetch).toHaveBeenCalled();
      expect(close).toHaveBeenCalled();
    } finally {
      vi.doUnmock("../../src/app/app");
      vi.doUnmock("../../src/adapters/db/drizzle/runtime");
      vi.doUnmock("../../src/config/env");
      vi.resetModules();
    }
  });
});
