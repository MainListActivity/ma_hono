import { describe, expect, it } from "vitest";

import { createApp } from "../../src/app/app";

describe("app smoke", () => {
  it("responds 404 for unknown routes", async () => {
    const app = createApp({
      adminBootstrapPasswordHash: "",
      adminWhitelist: [],
      managementApiToken: "",
      authDomain: "auth.example.test",
      oidcHost: "idp.example.test",
      totpRepository: {
        create: async () => undefined,
        findByTenantAndUser: async () => null,
        updateLastUsedWindow: async () => undefined
      },
      mfaPasskeyChallengeRepository: {
        create: async () => undefined,
        consumeByChallengeHash: async () => null
      },
      totpEncryptionKey: new Uint8Array(32)
    });

    const response = await app.request("http://localhost/unknown");

    expect(response.status).toBe(404);
  });
});
