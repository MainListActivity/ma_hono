import { expect, it } from "vitest";
import { browserAuthorizationRedirect } from "../../src/app/browser-authorization-redirect";

it("moves browser authorization to the session host without changing OAuth parameters", () => {
  const request = new Request("https://o.example.test/t/ck/authorize?state=a%2Bb&resource=https%3A%2F%2Fauth.example.test%2Fops");
  const response = browserAuthorizationRedirect(request, "o.example.test", "auth.example.test")!;
  const location = new URL(response.headers.get("location")!);
  expect(location.origin).toBe("https://auth.example.test");
  expect(location.pathname).toBe("/api/t/ck/authorize");
  expect(location.search).toBe(new URL(request.url).search);
  expect(browserAuthorizationRedirect(new Request(location), "o.example.test", "auth.example.test")).toBeNull();
  expect(browserAuthorizationRedirect(new Request("https://custom.example.test/authorize"), "o.example.test", "auth.example.test")).toBeNull();
});
