import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAdminRepository } from "../../src/adapters/db/memory/memory-admin-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryClientAuthMethodPolicyRepository } from "../../src/adapters/db/memory/memory-client-auth-method-policy-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryKeyRepository } from "../../src/adapters/db/memory/memory-key-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { createApp } from "../../src/app/app";
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import type { Client } from "../../src/domain/clients/types";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import type { Tenant } from "../../src/domain/tenants/types";

const acmeTenant: Tenant = {
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
};

const dbClient: Client = {
  id: "client_db_record",
  tenantId: "tenant_acme",
  clientId: "db-client",
  clientName: "Tenant DB",
  applicationType: "web",
  grantTypes: [],
  redirectUris: [],
  responseTypes: [],
  tokenEndpointAuthMethod: "none",
  clientSecretHash: null,
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "db",
  accessTokenAudience: "surrealdb"
};

const createSigner = async (): Promise<{
  material: SigningKeyMaterial;
  signer: SigningKeySigner;
}> => {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true
  });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const material: SigningKeyMaterial = {
    key: {
      id: "key_acme",
      tenantId: "tenant_acme",
      kid: "kid-acme",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      publicJwk: {
        ...publicJwk,
        alg: "RS256",
        kid: "kid-acme",
        use: "sig"
      }
    },
    privateJwk: {
      ...privateJwk,
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

const signIncomingUserToken = async (material: SigningKeyMaterial) => {
  const privateKey = await importJWK(material.privateJwk, "RS256");

  return await new SignJWT({
    sub: "user_123",
    email: "alice@example.test",
    scope: "openid"
  })
    .setProtectedHeader({
      alg: "RS256",
      kid: material.key.kid,
      typ: "JWT"
    })
    .setIssuer("https://idp.example.test/t/acme")
    .setAudience("app-client")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
};

const createBucket = (records: Record<string, unknown>) =>
  ({
    async get(key: string) {
      if (!(key in records)) {
        return null;
      }

      const value = records[key];

      return {
        async text() {
          return typeof value === "string" ? value : JSON.stringify(value);
        },
        async json<T>() {
          return value as T;
        }
      };
    }
  }) as unknown as R2Bucket;

const makeApp = async () => {
  const { material, signer } = await createSigner();
  const accessTokenClaimsRepository = new MemoryAccessTokenClaimsRepository();
  const fixedClaim: AccessTokenCustomClaim = {
    id: "claim_role_admin",
    clientId: dbClient.id,
    tenantId: "tenant_acme",
    claimName: "role",
    sourceType: "fixed",
    fixedValue: "admin",
    userField: null,
    hookField: null,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z"
  };
  await accessTokenClaimsRepository.createMany([fixedClaim]);

  const app = createApp({
    accessTokenClaimsRepository,
    adminBootstrapPasswordHash: "1:AQEBAQEBAQEBAQEBAQEBAQ:-niO1HggQYX5120bMdQ1NLtflreXdKdYKUoUQe1oPdI",
    adminWhitelist: ["admin@example.test"],
    adminRepository: new MemoryAdminRepository({
      adminUsers: [{ email: "admin@example.test", id: "admin_1", status: "active" }]
    }),
    auditRepository: new MemoryAuditRepository(),
    clientAuthMethodPolicyRepository: new MemoryClientAuthMethodPolicyRepository(),
    clientRepository: new MemoryClientRepository([dbClient]),
    keyMaterialBucket: createBucket({
      "db-templates/select-user.sql": "SELECT * FROM user WHERE id = $sub;",
      "db-config/surrealdb.json": {
        url: "https://surreal.example.test/sql",
        ns: "tenant_ns",
        db: "tenant_db"
      }
    }),
    keyRepository: new MemoryKeyRepository([material.key]),
    managementApiToken: "",
    oidcHost: "idp.example.test",
    authDomain: "auth.example.test",
    signer,
    tenantRepository: new MemoryTenantRepository([acmeTenant]),
    totpRepository: new MemoryTotpRepository(),
    mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
    totpEncryptionKey: new Uint8Array(32).fill(0)
  });

  return { app, material };
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("POST /db/execTemplate", () => {
  it("uses the tenant DB client to call SurrealDB with a Bearer access token", async () => {
    const { app, material } = await makeApp();
    const incomingToken = await signIncomingUserToken(material);
    const capturedRequests: Array<{
      url: string;
      headers: Headers;
      body: BodyInit | null | undefined;
    }> = [];

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        capturedRequests.push({
          url: url.toString(),
          headers: new Headers(init?.headers),
          body: init?.body
        });

        return new Response(JSON.stringify([{ status: "OK", result: [] }]), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      })
    );

    const response = await app.request("https://auth.example.test/db/execTemplate", {
      method: "POST",
      headers: {
        authorization: `Bearer ${incomingToken}`,
        "content-type": "application/json",
        "x-mp-tenant": "acme"
      },
      body: JSON.stringify({
        id: "select-user",
        params: { sub: "caller-supplied", limit: 10 }
      })
    });

    expect(response.status).toBe(200);
    const capturedRequest = capturedRequests[0];
    expect(capturedRequest).toBeDefined();
    if (capturedRequest === undefined) {
      throw new Error("SurrealDB request was not captured");
    }
    expect(capturedRequest.url).toContain("https://surreal.example.test/sql");
    expect(capturedRequest.url).toContain("sub=user_123");
    expect(capturedRequest.url).toContain("limit=10");
    expect(capturedRequest.headers.get("surreal-ns")).toBe("tenant_ns");
    expect(capturedRequest.headers.get("surreal-db")).toBe("tenant_db");
    expect(capturedRequest.body).toBe("SELECT * FROM user WHERE id = $sub;");

    const authorization = capturedRequest.headers.get("authorization") ?? "";
    const dbAccessToken = authorization.replace(/^Bearer\s+/i, "");
    const verificationKey = await importJWK(material.key.publicJwk as JWK, "RS256");
    const verified = await jwtVerify(dbAccessToken, verificationKey, {
      issuer: "https://idp.example.test/t/acme",
      audience: "surrealdb"
    });

    expect(verified.payload.sub).toBe("admin");
    expect(verified.payload.username).toBe("admin");
    expect(verified.payload.client_id).toBe("db-client");
    expect(verified.payload.scope).toBe("surrealdb");
    expect(verified.payload.role).toBe("admin");
  });

  it("rejects a second DB client for the same tenant", async () => {
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
    const login = await app.request("https://idp.example.test/admin/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "admin@example.test", password: "bootstrap-secret" })
    });
    const loginBody = (await login.json()) as { session_token: string };
    const payload = {
      client_name: "Tenant DB",
      client_profile: "db",
      application_type: "web",
      redirect_uris: [],
      token_endpoint_auth_method: "none",
      grant_types: [],
      response_types: [],
      access_token_audience: "surrealdb"
    };

    const first = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/clients",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify(payload)
      }
    );
    expect(first.status).toBe(201);

    const second = await app.request(
      "https://idp.example.test/admin/tenants/tenant_acme/clients",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${loginBody.session_token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify(payload)
      }
    );
    expect(second.status).toBe(409);
    await expect(second.json()).resolves.toEqual({ error: "db_client_already_exists" });
  });
});
