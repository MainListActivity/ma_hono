/** Keep browser sessions host-only on auth; protocol discovery/issuer stay on o. */
export function browserAuthorizationRedirect(request: Request, oidcHost: string, authHost: string): Response | null {
  const url = new URL(request.url);
  if (request.method !== "GET" || url.hostname !== oidcHost || !/^\/t\/[^/]+\/authorize$/u.test(url.pathname)) return null;
  url.hostname = authHost;
  url.pathname = `/api${url.pathname}`;
  return new Response(null, { status: 302, headers: { location: url.toString(), "cache-control": "no-store" } });
}
