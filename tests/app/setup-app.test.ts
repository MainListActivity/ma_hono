import { describe, it, expect } from "vitest";
import { createSetupApp } from "../../src/app/setup-app";

const makeMockDb = () => {
  const db = {
    prepare: (_sql: string) => ({
      bind: (..._args: unknown[]) => ({
        all: async () => ({ results: [] }),
        run: async () => ({ success: true })
      }),
      run: async () => ({ success: true })
    }),
    batch: async (stmts: unknown[]) => {
      return stmts.map(() => ({ success: true, results: [] }));
    }
  } as unknown as D1Database;
  return db;
};

describe("GET /", () => {
  it("redirects to /setup", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/"));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/setup");
  });
});

describe("GET /setup", () => {
  it("renders form with 200", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/setup", {
      headers: { host: "auth.example.com" }
    }));
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("example.com");
    expect(body).toContain("root_domain");
    expect(body).toContain("admin_whitelist");
    expect(body).toContain("admin_bootstrap_password");
    expect(body).toContain("management_api_token");
  });
});

describe("POST /setup", () => {
  const validBody = new URLSearchParams({
    root_domain: "example.com",
    admin_whitelist: "admin@example.com",
    admin_bootstrap_password: "s3cur3P@ssw0rd!",
    admin_bootstrap_password_confirm: "s3cur3P@ssw0rd!",
    management_api_token: "tok_abc"
  });

  it("redirects to auth subdomain on valid submission", async () => {
    const app = createSetupApp(makeMockDb());
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: validBody.toString()
    }));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://auth.example.com/");
  });

  it("returns 400 when passwords do not match", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("admin_bootstrap_password_confirm", "different");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("do not match");
  });

  it("returns 400 when a required field is empty", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("admin_whitelist", "");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
  });

  it("returns 400 when root_domain contains scheme", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("root_domain", "https://example.com");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
  });

  it("returns 400 when root_domain contains a port number", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("root_domain", "example.com:8080");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
  });

  it("HTML-escapes reflected root_domain value on validation failure", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("root_domain", '"><script>alert(1)</script>');
    body.set("admin_bootstrap_password_confirm", "mismatch");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).not.toContain("<script>");
    expect(text).toContain("&lt;script&gt;");
  });

  it("HTML-escapes reflected managementApiToken value on validation failure", async () => {
    const app = createSetupApp(makeMockDb());
    const body = new URLSearchParams(validBody);
    body.set("management_api_token", '"><script>alert(2)</script>');
    body.set("admin_bootstrap_password_confirm", "mismatch");
    const res = await app.fetch(new Request("http://localhost/setup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }));
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).not.toContain("<script>");
    expect(text).toContain("&lt;script&gt;");
  });
});
