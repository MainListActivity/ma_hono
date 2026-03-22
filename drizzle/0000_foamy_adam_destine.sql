CREATE TABLE `admin_users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `admin_users_email_unique` ON `admin_users` (`email`);--> statement-breakpoint
CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`actor_type` text NOT NULL,
	`actor_id` text,
	`tenant_id` text,
	`event_type` text NOT NULL,
	`target_type` text,
	`target_id` text,
	`payload` text,
	`occurred_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `audit_events_tenant_id_idx` ON `audit_events` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `audit_events_event_type_idx` ON `audit_events` (`event_type`);--> statement-breakpoint
CREATE TABLE `authorization_codes` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`issuer` text NOT NULL,
	`client_id` text NOT NULL,
	`user_id` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`scope` text NOT NULL,
	`nonce` text,
	`code_challenge` text NOT NULL,
	`code_challenge_method` text NOT NULL,
	`token_hash` text NOT NULL,
	`expires_at` text NOT NULL,
	`consumed_at` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`user_id`) REFERENCES `users`(`tenant_id`,`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`client_id`) REFERENCES `oidc_clients`(`tenant_id`,`client_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `authorization_codes_tenant_id_idx` ON `authorization_codes` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `authorization_codes_user_id_idx` ON `authorization_codes` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `authorization_codes_token_hash_active_unique` ON `authorization_codes` (`token_hash`) WHERE "authorization_codes"."consumed_at" IS NULL;--> statement-breakpoint
CREATE TABLE `client_auth_method_policies` (
	`client_id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`password_enabled` integer DEFAULT false NOT NULL,
	`password_allow_registration` integer DEFAULT false NOT NULL,
	`magic_link_enabled` integer DEFAULT false NOT NULL,
	`magic_link_allow_registration` integer DEFAULT false NOT NULL,
	`passkey_enabled` integer DEFAULT false NOT NULL,
	`passkey_allow_registration` integer DEFAULT false NOT NULL,
	`google_enabled` integer DEFAULT false NOT NULL,
	`apple_enabled` integer DEFAULT false NOT NULL,
	`facebook_enabled` integer DEFAULT false NOT NULL,
	`wechat_enabled` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`client_id`) REFERENCES `oidc_clients`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `client_auth_method_policies_tenant_id_idx` ON `client_auth_method_policies` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `email_login_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`issuer` text NOT NULL,
	`token_hash` text NOT NULL,
	`redirect_after_login` text NOT NULL,
	`expires_at` text NOT NULL,
	`consumed_at` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`user_id`) REFERENCES `users`(`tenant_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `email_login_tokens_tenant_id_idx` ON `email_login_tokens` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `email_login_tokens_user_id_idx` ON `email_login_tokens` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `email_login_tokens_token_hash_active_unique` ON `email_login_tokens` (`token_hash`) WHERE "email_login_tokens"."consumed_at" IS NULL;--> statement-breakpoint
CREATE TABLE `login_challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`issuer` text NOT NULL,
	`client_id` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`scope` text NOT NULL,
	`state` text NOT NULL,
	`code_challenge` text NOT NULL,
	`code_challenge_method` text NOT NULL,
	`nonce` text,
	`token_hash` text NOT NULL,
	`expires_at` text NOT NULL,
	`consumed_at` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`client_id`) REFERENCES `oidc_clients`(`tenant_id`,`client_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `login_challenges_tenant_id_idx` ON `login_challenges` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `login_challenges_token_hash_active_unique` ON `login_challenges` (`token_hash`) WHERE "login_challenges"."consumed_at" IS NULL;--> statement-breakpoint
CREATE TABLE `oidc_clients` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`client_id` text NOT NULL,
	`client_secret_hash` text,
	`client_name` text NOT NULL,
	`application_type` text NOT NULL,
	`trust_level` text DEFAULT 'first_party_trusted' NOT NULL,
	`consent_policy` text DEFAULT 'skip' NOT NULL,
	`token_endpoint_auth_method` text NOT NULL,
	`redirect_uris` text NOT NULL,
	`grant_types` text NOT NULL,
	`response_types` text NOT NULL,
	`created_by` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `oidc_clients_tenant_id_idx` ON `oidc_clients` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oidc_clients_client_id_unique` ON `oidc_clients` (`client_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oidc_clients_tenant_id_client_id_unique` ON `oidc_clients` (`tenant_id`,`client_id`);--> statement-breakpoint
CREATE TABLE `platform_config` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `signing_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text,
	`kid` text NOT NULL,
	`alg` text NOT NULL,
	`kty` text NOT NULL,
	`public_jwk` text NOT NULL,
	`private_key_ref` text,
	`status` text NOT NULL,
	`activated_at` text,
	`retire_at` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `signing_keys_tenant_id_idx` ON `signing_keys` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `signing_keys_kid_unique` ON `signing_keys` (`kid`);--> statement-breakpoint
CREATE TABLE `tenant_auth_method_policies` (
	`tenant_id` text PRIMARY KEY NOT NULL,
	`password_enabled` integer NOT NULL,
	`email_magic_link_enabled` integer NOT NULL,
	`passkey_enabled` integer NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `tenant_auth_method_policies_password_enabled_idx` ON `tenant_auth_method_policies` (`password_enabled`);--> statement-breakpoint
CREATE TABLE `tenant_issuers` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`issuer_type` text NOT NULL,
	`issuer_url` text NOT NULL,
	`domain` text,
	`is_primary` integer NOT NULL,
	`verification_status` text NOT NULL,
	`verified_at` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `tenant_issuers_tenant_id_idx` ON `tenant_issuers` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `tenant_issuers_issuer_url_unique` ON `tenant_issuers` (`issuer_url`);--> statement-breakpoint
CREATE UNIQUE INDEX `tenant_issuers_domain_unique` ON `tenant_issuers` (`domain`);--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`display_name` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tenants_slug_unique` ON `tenants` (`slug`);--> statement-breakpoint
CREATE INDEX `tenants_status_idx` ON `tenants` (`status`);--> statement-breakpoint
CREATE TABLE `user_invitations` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`purpose` text NOT NULL,
	`expires_at` text NOT NULL,
	`consumed_at` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`user_id`) REFERENCES `users`(`tenant_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `user_invitations_tenant_id_idx` ON `user_invitations` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `user_invitations_user_id_idx` ON `user_invitations` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `user_invitations_token_hash_active_unique` ON `user_invitations` (`token_hash`) WHERE "user_invitations"."consumed_at" IS NULL;--> statement-breakpoint
CREATE TABLE `user_password_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`password_hash` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`user_id`) REFERENCES `users`(`tenant_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `user_password_credentials_tenant_id_idx` ON `user_password_credentials` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `user_password_credentials_user_id_unique` ON `user_password_credentials` (`user_id`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`email` text NOT NULL,
	`email_verified` integer NOT NULL,
	`username` text,
	`display_name` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `users_tenant_id_idx` ON `users` (`tenant_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_tenant_id_id_unique` ON `users` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_tenant_id_email_unique` ON `users` (`tenant_id`,`email`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_tenant_id_username_unique` ON `users` (`tenant_id`,`username`);--> statement-breakpoint
CREATE TABLE `webauthn_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`credential_id` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer NOT NULL,
	`transports` text,
	`device_type` text NOT NULL,
	`backed_up` integer NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tenant_id`,`user_id`) REFERENCES `users`(`tenant_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `webauthn_credentials_tenant_id_idx` ON `webauthn_credentials` (`tenant_id`);--> statement-breakpoint
CREATE INDEX `webauthn_credentials_user_id_idx` ON `webauthn_credentials` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `webauthn_credentials_credential_id_unique` ON `webauthn_credentials` (`credential_id`);