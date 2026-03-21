import { describe, it, expect } from "vitest";
import { hashPasswordPbkdf2, verifyPasswordPbkdf2 } from "../src/lib/pbkdf2";

describe("hashPasswordPbkdf2", () => {
  it("returns a string with format iterations:salt:hash", async () => {
    const hash = await hashPasswordPbkdf2("secret");
    const parts = hash.split(":");
    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe("100000");
    expect(parts[1].length).toBeGreaterThan(0);
    expect(parts[2].length).toBeGreaterThan(0);
  });

  it("produces different hashes for the same password (random salt)", async () => {
    const hash1 = await hashPasswordPbkdf2("secret");
    const hash2 = await hashPasswordPbkdf2("secret");
    expect(hash1).not.toBe(hash2);
  });
});

describe("verifyPasswordPbkdf2", () => {
  it("returns true for correct password", async () => {
    const hash = await hashPasswordPbkdf2("correct-horse-battery-staple");
    expect(await verifyPasswordPbkdf2("correct-horse-battery-staple", hash)).toBe(true);
  });

  it("returns false for wrong password", async () => {
    const hash = await hashPasswordPbkdf2("correct-horse-battery-staple");
    expect(await verifyPasswordPbkdf2("wrong-password", hash)).toBe(false);
  });

  it("returns false for malformed hash string", async () => {
    expect(await verifyPasswordPbkdf2("password", "notahash")).toBe(false);
    expect(await verifyPasswordPbkdf2("password", "a:b")).toBe(false);
    expect(await verifyPasswordPbkdf2("password", "")).toBe(false);
  });
});
