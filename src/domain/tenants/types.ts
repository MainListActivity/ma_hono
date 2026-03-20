export type TenantStatus = "active" | "disabled";

export type IssuerType = "platform_path" | "custom_domain";

export type TenantIssuerVerificationStatus = "pending" | "verified" | "failed";

export interface TenantIssuer {
  id: string;
  issuerType: IssuerType;
  issuerUrl: string;
  domain: string | null;
  isPrimary: boolean;
  verificationStatus: TenantIssuerVerificationStatus;
}

export interface Tenant {
  id: string;
  slug: string;
  displayName: string;
  status: TenantStatus;
  issuers: TenantIssuer[];
}

export interface ResolvedIssuerContext {
  tenant: Tenant;
  issuer: string;
  issuerPathPrefix: string;
  source: IssuerType;
  requestHost: string;
}
