CREATE TABLE `client_auth_method_policies` (
  `client_id` text PRIMARY KEY NOT NULL,
  `tenant_id` text NOT NULL,
  `password_enabled` integer NOT NULL DEFAULT 0,
  `password_allow_registration` integer NOT NULL DEFAULT 0,
  `magic_link_enabled` integer NOT NULL DEFAULT 0,
  `magic_link_allow_registration` integer NOT NULL DEFAULT 0,
  `passkey_enabled` integer NOT NULL DEFAULT 0,
  `passkey_allow_registration` integer NOT NULL DEFAULT 0,
  `google_enabled` integer NOT NULL DEFAULT 0,
  `apple_enabled` integer NOT NULL DEFAULT 0,
  `facebook_enabled` integer NOT NULL DEFAULT 0,
  `wechat_enabled` integer NOT NULL DEFAULT 0,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL,
  FOREIGN KEY (`client_id`) REFERENCES `oidc_clients`(`id`) ON UPDATE no action ON DELETE cascade,
  FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
CREATE INDEX `client_auth_method_policies_tenant_id_idx` ON `client_auth_method_policies` (`tenant_id`);
