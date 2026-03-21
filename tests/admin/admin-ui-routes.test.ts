import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  ADMIN_UI_BASE_PATH,
  LOGIN_ROUTE,
  TENANTS_ROUTE,
  adminHref,
  tenantUsersRoute
} from "../../admin/src/routes";

describe("admin UI route helpers", () => {
  it("prefixes admin routes with /ui for browser-visible URLs", () => {
    expect(ADMIN_UI_BASE_PATH).toBe("/ui");
    expect(adminHref(LOGIN_ROUTE)).toBe("/ui/login");
    expect(adminHref(TENANTS_ROUTE)).toBe("/ui/tenants");
    expect(adminHref(tenantUsersRoute("tenant_123"))).toBe("/ui/tenants/tenant_123/users");
  });
});

describe("admin Pages redirects", () => {
  it("rewrites only /ui routes to the SPA entrypoint", () => {
    const redirects = readFileSync(
      new URL("../../admin/public/_redirects", import.meta.url),
      "utf8"
    ).trim();

    expect(redirects).toBe(
      ["/ /ui 302", "/ui /index.html 200", "/ui/* /index.html 200"].join("\n")
    );
  });
});
