import { describe, expect, it } from "vitest";

import { adminClientRegistrationSchema } from "../../src/domain/clients/admin-registration-schema";

describe("Admin Client Registration Schema", () => {
  const baseSpa = {
    client_name: "My SPA",
    client_profile: "spa",
    application_type: "web",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"],
    redirect_uris: ["https://app.example.com/callback"],
    access_token_audience: "https://api.example.com"
  };

  it("accepts a valid SPA client", () => {
    const result = adminClientRegistrationSchema.safeParse(baseSpa);
    expect(result.success).toBe(true);
  });

  it("rejects SPA without audience", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_audience: undefined
    });
    expect(result.success).toBe(false);
  });

  it("rejects SPA with confidential auth method", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      token_endpoint_auth_method: "client_secret_basic"
    });
    expect(result.success).toBe(false);
  });

  it("rejects SPA with application_type native", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      application_type: "native"
    });
    expect(result.success).toBe(false);
  });

  it("accepts a valid web client without audience", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "My Web App",
      client_profile: "web",
      application_type: "web",
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: ["https://app.example.com/callback"]
    });
    expect(result.success).toBe(true);
  });

  it("rejects web client with auth method none", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "My Web App",
      client_profile: "web",
      application_type: "web",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: ["https://app.example.com/callback"]
    });
    expect(result.success).toBe(false);
  });

  it("rejects reserved claim names", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "sub", source_type: "fixed", fixed_value: "override" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("rejects user_field claims with invalid field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "role", source_type: "user_field", user_field: "password_hash" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("accepts valid custom claims", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "ns", source_type: "fixed", fixed_value: "my_namespace" },
        { claim_name: "user_email", source_type: "user_field", user_field: "email" }
      ]
    });
    expect(result.success).toBe(true);
  });

  it("rejects fixed claims without fixed_value", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [{ claim_name: "ns", source_type: "fixed" }]
    });
    expect(result.success).toBe(false);
  });

  it("rejects user_field claims without user_field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [{ claim_name: "user_email", source_type: "user_field" }]
    });
    expect(result.success).toBe(false);
  });
});
