import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import { MemoryAccessTokenClaimsRepository } from "../../src/adapters/db/memory/memory-access-token-claims-repository";
import { MemoryAuditRepository } from "../../src/adapters/db/memory/memory-audit-repository";
import { MemoryAuthorizationCodeRepository } from "../../src/adapters/db/memory/memory-authorization-code-repository";
import { MemoryClientRepository } from "../../src/adapters/db/memory/memory-client-repository";
import { MemoryMfaPasskeyChallengeRepository } from "../../src/adapters/db/memory/memory-mfa-passkey-challenge-repository";
import { MemoryTenantRepository } from "../../src/adapters/db/memory/memory-tenant-repository";
import { MemoryTotpRepository } from "../../src/adapters/db/memory/memory-totp-repository";
import { MemoryUserRepository } from "../../src/adapters/db/memory/memory-user-repository";
import { createApp } from "../../src/app/app";
import type { AuthorizationCode } from "../../src/domain/authorization/types";
import type { AccessTokenCustomClaim } from "../../src/domain/clients/access-token-claims-types";
import { resolveCustomClaims } from "../../src/domain/clients/resolve-custom-claims";
import type { SigningKeySigner } from "../../src/domain/keys/signer";
import type { SigningKeyMaterial } from "../../src/domain/keys/types";
import type { Client } from "../../src/domain/clients/types";
import type { User } from "../../src/domain/users/types";
import { sha256Base64Url } from "../../src/lib/hash";

const baseUser: User = {
  id: "user_1",
  tenantId: "tenant_1",
  email: "alice@example.com",
  emailVerified: true,
  username: "alice",
  displayName: "Alice Smith",
  status: "active",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z"
};

const makeClaim = (
  overrides: Partial<AccessTokenCustomClaim>
): AccessTokenCustomClaim => ({
  id: "claim_1",
  clientId: "client_1",
  tenantId: "tenant_1",
  claimName: "custom",
  sourceType: "fixed",
  fixedValue: null,
  userField: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides
});

describe("resolveCustomClaims", () => {
  it("resolves fixed claims", () => {
    const claims = [
      makeClaim({ claimName: "ns", sourceType: "fixed", fixedValue: "my_ns" })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ns: "my_ns" });
  });

  it("resolves user_field id", () => {
    const claims = [
      makeClaim({ claimName: "uid", sourceType: "user_field", userField: "id" })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ uid: "user_1" });
  });

  it("resolves user_field email", () => {
    const claims = [
      makeClaim({
        claimName: "user_email",
        sourceType: "user_field",
        userField: "email"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ user_email: "alice@example.com" });
  });

  it("resolves user_field email_verified", () => {
    const claims = [
      makeClaim({
        claimName: "ev",
        sourceType: "user_field",
        userField: "email_verified"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ev: true });
  });

  it("resolves user_field username", () => {
    const claims = [
      makeClaim({
        claimName: "uname",
        sourceType: "user_field",
        userField: "username"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ uname: "alice" });
  });

  it("resolves user_field display_name", () => {
    const claims = [
      makeClaim({
        claimName: "name",
        sourceType: "user_field",
        userField: "display_name"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ name: "Alice Smith" });
  });

  it("omits user_field claim when value is null", () => {
    const user = { ...baseUser, username: null };
    const claims = [
      makeClaim({
        claimName: "uname",
        sourceType: "user_field",
        userField: "username"
      })
    ];

    const result = resolveCustomClaims(claims, user);

    expect(result).toEqual({});
  });

  it("resolves multiple claims", () => {
    const claims = [
      makeClaim({
        id: "c1",
        claimName: "ns",
        sourceType: "fixed",
        fixedValue: "my_ns"
      }),
      makeClaim({
        id: "c2",
        claimName: "user_email",
        sourceType: "user_field",
        userField: "email"
      })
    ];

    const result = resolveCustomClaims(claims, baseUser);

    expect(result).toEqual({ ns: "my_ns", user_email: "alice@example.com" });
  });

  it("returns empty object when no claims", () => {
    const result = resolveCustomClaims([], baseUser);

    expect(result).toEqual({});
  });
});

const tenantRepository = new MemoryTenantRepository([
  {
    id: "tenant_1",
    slug: "tenant-1",
    displayName: "Tenant 1",
    status: "active",
    issuers: [
      {
        id: "issuer_tenant_1",
        issuerType: "platform_path",
        issuerUrl: "https://idp.example.test/t/tenant-1",
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
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const material: SigningKeyMaterial = {
    key: {
      id: "key_tenant_1",
      tenantId: "tenant_1",
      kid: "kid-tenant-1",
      alg: "RS256",
      kty: "RSA",
      status: "active",
      publicJwk: {
        ...publicJwk,
        alg: "RS256",
        kid: "kid-tenant-1",
        use: "sig"
      }
    },
    privateJwk: {
      ...privateJwk,
      alg: "RS256",
      kid: "kid-tenant-1"
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
  accessTokenAudience,
  clientId,
  internalId = `record_${clientId}`,
  tokenEndpointAuthMethod = "none"
}: {
  accessTokenAudience: string | null;
  clientId: string;
  internalId?: string;
  tokenEndpointAuthMethod?: Client["tokenEndpointAuthMethod"];
}): Promise<Client> => ({
  id: internalId,
  tenantId: "tenant_1",
  clientId,
  clientName: clientId,
  applicationType: "web",
  grantTypes: ["authorization_code"],
  redirectUris: ["https://app.example.com/callback"],
  responseTypes: ["code"],
  tokenEndpointAuthMethod,
  clientSecretHash: null,
  trustLevel: "first_party_trusted",
  consentPolicy: "skip",
  clientProfile: "spa",
  accessTokenAudience
});

const seedAuthorizationCode = async ({
  clientId,
  code,
  codeRepository,
  userId
}: {
  clientId: string;
  code: string;
  codeRepository: MemoryAuthorizationCodeRepository;
  userId: string;
}) => {
  const authorizationCode: AuthorizationCode = {
    id: `authorization_code_${code}`,
    tenantId: "tenant_1",
    issuer: "https://idp.example.test/t/tenant-1",
    clientId,
    userId,
    redirectUri: "https://app.example.com/callback",
    scope: "openid profile",
    nonce: "nonce_123",
    codeChallenge: await sha256Base64Url("verifier-123456"),
    codeChallengeMethod: "S256",
    tokenHash: await sha256Base64Url(code),
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    consumedAt: null,
    createdAt: new Date().toISOString()
  };

  await codeRepository.create(authorizationCode);
};

const exchangeCode = async ({
  app,
  clientId,
  code
}: {
  app: ReturnType<typeof createApp>;
  clientId: string;
  code: string;
}) => {
  const body = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: "verifier-123456",
    grant_type: "authorization_code",
    redirect_uri: "https://app.example.com/callback"
  });

  return app.request("https://idp.example.test/t/tenant-1/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: body.toString()
  });
};

const createTokenTestApp = async ({
  client,
  claims = [],
  user = baseUser
}: {
  client: Client;
  claims?: AccessTokenCustomClaim[];
  user?: User;
}) => {
  const { signer } = await createSigner();
  const authorizationCodeRepository = new MemoryAuthorizationCodeRepository();
  const accessTokenClaimsRepository = new MemoryAccessTokenClaimsRepository();

  if (claims.length > 0) {
    await accessTokenClaimsRepository.createMany(claims);
  }

  return {
    app: createApp({
      accessTokenClaimsRepository,
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      auditRepository: new MemoryAuditRepository(),
      authorizationCodeRepository,
      clientRepository: new MemoryClientRepository([client]),
      managementApiToken: "",
      oidcHost: "idp.example.test",
      authDomain: "auth.example.test",
      signer,
      tenantRepository,
      totpRepository: new MemoryTotpRepository(),
      mfaPasskeyChallengeRepository: new MemoryMfaPasskeyChallengeRepository(),
      totpEncryptionKey: new Uint8Array(32).fill(0),
      userRepository: new MemoryUserRepository({ users: [user] })
    }),
    authorizationCodeRepository
  };
};

describe("Token endpoint with custom claims", () => {
  it("includes configured audience in access token", async () => {
    const client = await createClient({
      clientId: "spa_client_aud",
      accessTokenAudience: "https://api.example.com"
    });
    const { app, authorizationCodeRepository } = await createTokenTestApp({ client });

    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-audience",
      codeRepository: authorizationCodeRepository,
      userId: baseUser.id
    });

    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-audience"
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
    };
    const accessToken = decodeJwt(body.access_token);

    expect(accessToken.aud).toBe("https://api.example.com");
    expect(accessToken.client_id).toBe(client.clientId);
  });

  it("includes fixed custom claims in access token", async () => {
    const client = await createClient({
      clientId: "spa_client_fixed",
      accessTokenAudience: "https://api.example.com"
    });
    const { app, authorizationCodeRepository } = await createTokenTestApp({
      client,
      claims: [
        makeClaim({
          clientId: client.id,
          tenantId: client.tenantId,
          claimName: "ns",
          sourceType: "fixed",
          fixedValue: "my_namespace"
        })
      ]
    });

    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-fixed-claim",
      codeRepository: authorizationCodeRepository,
      userId: baseUser.id
    });

    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-fixed-claim"
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
    };
    const accessToken = decodeJwt(body.access_token);

    expect(accessToken.ns).toBe("my_namespace");
  });

  it("includes user-field mapped claims in access token", async () => {
    const client = await createClient({
      clientId: "spa_client_user_fields",
      accessTokenAudience: "https://api.example.com"
    });
    const { app, authorizationCodeRepository } = await createTokenTestApp({
      client,
      claims: [
        makeClaim({
          id: "claim_email",
          clientId: client.id,
          tenantId: client.tenantId,
          claimName: "user_email",
          sourceType: "user_field",
          userField: "email"
        }),
        makeClaim({
          id: "claim_email_verified",
          clientId: client.id,
          tenantId: client.tenantId,
          claimName: "email_verified_flag",
          sourceType: "user_field",
          userField: "email_verified"
        })
      ]
    });

    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-user-claims",
      codeRepository: authorizationCodeRepository,
      userId: baseUser.id
    });

    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-user-claims"
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
    };
    const accessToken = decodeJwt(body.access_token);

    expect(accessToken.user_email).toBe(baseUser.email);
    expect(accessToken.email_verified_flag).toBe(true);
  });

  it("does NOT include custom claims in ID token", async () => {
    const client = await createClient({
      clientId: "spa_client_id_token",
      accessTokenAudience: "https://api.example.com"
    });
    const { app, authorizationCodeRepository } = await createTokenTestApp({
      client,
      claims: [
        makeClaim({
          clientId: client.id,
          tenantId: client.tenantId,
          claimName: "user_email",
          sourceType: "user_field",
          userField: "email"
        })
      ]
    });

    await seedAuthorizationCode({
      clientId: client.clientId,
      code: "code-id-token",
      codeRepository: authorizationCodeRepository,
      userId: baseUser.id
    });

    const response = await exchangeCode({
      app,
      clientId: client.clientId,
      code: "code-id-token"
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      access_token: string;
      id_token: string;
    };
    const accessToken = decodeJwt(body.access_token);
    const idToken = decodeJwt(body.id_token);

    expect(accessToken.user_email).toBe(baseUser.email);
    expect(idToken.user_email).toBeUndefined();
  });
});
