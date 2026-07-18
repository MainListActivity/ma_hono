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

  it("accepts an HTTPS initiate_login_uri", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      initiate_login_uri: "https://app.example.com/login"
    });

    expect(result.success).toBe(true);
  });

  it("rejects a non-HTTPS initiate_login_uri", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      initiate_login_uri: "http://app.example.com/login"
    });

    expect(result.success).toBe(false);
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

  it("accepts a valid DB client without interactive OIDC metadata", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "Tenant SurrealDB",
      client_profile: "db",
      application_type: "web",
      token_endpoint_auth_method: "none",
      grant_types: [],
      response_types: [],
      redirect_uris: [],
      access_token_audience: "surrealdb",
      access_token_custom_claims: [
        { claim_name: "role", source_type: "fixed", fixed_value: "admin" }
      ]
    });
    expect(result.success).toBe(true);
  });

  it("rejects DB clients with user-field custom claims", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "Tenant SurrealDB",
      client_profile: "db",
      application_type: "web",
      token_endpoint_auth_method: "none",
      grant_types: [],
      response_types: [],
      redirect_uris: [],
      access_token_custom_claims: [
        { claim_name: "email", source_type: "user_field", user_field: "email" }
      ]
    });
    expect(result.success).toBe(false);
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

  it("accepts hook claims with a hook_field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      claim_hook_url: "https://app.example.test/api/idp/claims",
      claim_hook_auth_header_name: "x-idp-secret",
      claim_hook_auth_header_value: "tenant-secret",
      access_token_custom_claims: [
        { claim_name: "https://surrealdb.com/db", source_type: "hook", hook_field: "db" },
        { claim_name: "can_create_workspace", source_type: "hook", hook_field: "can_create_workspace" }
      ]
    });
    expect(result.success).toBe(true);
  });

  it("rejects hook claims without a claim hook url", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [
        { claim_name: "https://surrealdb.com/db", source_type: "hook", hook_field: "db" }
      ]
    });
    expect(result.success).toBe(false);
  });

  it("rejects partial claim hook auth header config", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      claim_hook_url: "https://app.example.test/api/idp/claims",
      claim_hook_auth_header_name: "x-idp-secret"
    });
    expect(result.success).toBe(false);
  });

  it("rejects hook claims without hook_field", () => {
    const result = adminClientRegistrationSchema.safeParse({
      ...baseSpa,
      access_token_custom_claims: [{ claim_name: "scope_db", source_type: "hook" }]
    });
    expect(result.success).toBe(false);
  });

  it("rejects DB clients with hook custom claims", () => {
    const result = adminClientRegistrationSchema.safeParse({
      client_name: "Tenant SurrealDB",
      client_profile: "db",
      application_type: "web",
      token_endpoint_auth_method: "none",
      grant_types: [],
      response_types: [],
      redirect_uris: [],
      access_token_custom_claims: [
        { claim_name: "db_scope", source_type: "hook", hook_field: "db" }
      ]
    });
    expect(result.success).toBe(false);
  });
});
