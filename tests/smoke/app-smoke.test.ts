import { describe, expect, it } from "vitest";

import { createApp } from "../../src/app/app";

describe("app smoke", () => {
  it("responds 404 for unknown routes", async () => {
    const app = createApp();

    const response = await app.request("http://localhost/unknown");

    expect(response.status).toBe(404);
  });
});
