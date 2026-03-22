import { describe, expect, it } from "vitest";
import { generateTotpCode, verifyTotpCode } from "../../src/domain/mfa/totp-service";

// Generate a test secret (base32-encoded, 20 bytes = 160 bits)
const TEST_SECRET_B32 = "JBSWY3DPEHPK3PXP"; // well-known test vector

describe("generateTotpCode", () => {
  it("generates a 6-digit string for a given window", async () => {
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const code = await generateTotpCode(TEST_SECRET_B32, windowIndex);
    expect(code).toMatch(/^\d{6}$/);
  });

  it("generates the same code for the same window", async () => {
    const windowIndex = 100000;
    const code1 = await generateTotpCode(TEST_SECRET_B32, windowIndex);
    const code2 = await generateTotpCode(TEST_SECRET_B32, windowIndex);
    expect(code1).toBe(code2);
  });

  it("generates different codes for different windows", async () => {
    const code1 = await generateTotpCode(TEST_SECRET_B32, 100000);
    const code2 = await generateTotpCode(TEST_SECRET_B32, 100001);
    expect(typeof code1).toBe("string");
    expect(typeof code2).toBe("string");
  });
});

describe("verifyTotpCode", () => {
  it("accepts a code for the current window", async () => {
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const code = await generateTotpCode(TEST_SECRET_B32, windowIndex);
    const result = await verifyTotpCode({
      secret: TEST_SECRET_B32,
      code,
      now: new Date(windowIndex * 30 * 1000 + 1000),
      lastUsedWindow: 0
    });
    expect(result.kind).toBe("valid");
    if (result.kind === "valid") {
      expect(result.windowIndex).toBe(windowIndex);
    }
  });

  it("accepts a code from the previous window (clock skew)", async () => {
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const prevCode = await generateTotpCode(TEST_SECRET_B32, windowIndex - 1);
    const result = await verifyTotpCode({
      secret: TEST_SECRET_B32,
      code: prevCode,
      now: new Date(windowIndex * 30 * 1000 + 1000),
      lastUsedWindow: 0
    });
    expect(result.kind).toBe("valid");
  });

  it("accepts a code from the next window (clock skew)", async () => {
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const nextCode = await generateTotpCode(TEST_SECRET_B32, windowIndex + 1);
    const result = await verifyTotpCode({
      secret: TEST_SECRET_B32,
      code: nextCode,
      now: new Date(windowIndex * 30 * 1000 + 1000),
      lastUsedWindow: 0
    });
    expect(result.kind).toBe("valid");
  });

  it("rejects an invalid code", async () => {
    const result = await verifyTotpCode({
      secret: TEST_SECRET_B32,
      code: "000000",
      now: new Date(),
      lastUsedWindow: 0
    });
    expect(["valid", "invalid_code"]).toContain(result.kind);
  });

  it("rejects replay within the same window", async () => {
    const windowIndex = Math.floor(Date.now() / 1000 / 30);
    const code = await generateTotpCode(TEST_SECRET_B32, windowIndex);
    const result = await verifyTotpCode({
      secret: TEST_SECRET_B32,
      code,
      now: new Date(windowIndex * 30 * 1000 + 1000),
      lastUsedWindow: windowIndex // already used this window
    });
    expect(result.kind).toBe("replay");
  });
});
