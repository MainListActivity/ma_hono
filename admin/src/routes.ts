export const ADMIN_UI_BASE_PATH = "/ui";

export const LOGIN_ROUTE = "/login";
export const TENANTS_ROUTE = "/tenants";

export const tenantUsersRoute = (tenantId: string) => `/tenants/${tenantId}/users`;

export const adminHref = (route: string) =>
  route === "/" ? ADMIN_UI_BASE_PATH : `${ADMIN_UI_BASE_PATH}${route.startsWith("/") ? route : `/${route}`}`;
