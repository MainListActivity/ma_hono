# AGENTS.md

## Project Structure
- src: hono code, domain is `auth.{domain}/api*` and `o.{domain}*`
- admin: ui code, domain is `auth.{domain}/*`. Tenant Login Page, Admin Login, User Information Page, MFA Page
- test: test code
- drizzle/migrations: db migration code, use `db:migrate:remote` to apply
- docs: docs code


## Purpose

This repository will become a multi-tenant identity provider (IdP) and authentication backend.

End users sign in to this service. Other applications trust the authenticated user through standards-based identity protocols exposed by this service, especially OpenID Connect discovery metadata, signed tokens, and a published JWKS endpoint.

This document defines the default context, architectural constraints, and decision rules for AI coding agents working in this repository.

## Locked Technology Decisions

- Use TypeScript only.
- Use Hono only for the HTTP application layer.
- Use Cloudflare Workers as the only runtime target.
- Use Cloudflare-native storage and platform services by default: D1, R2, and KV.

## Product Definition

The product is an authentication backend and IdP for first-party and third-party applications.

Core expectations:

- The user logs in to this service, not directly to each relying application.
- Relying applications trust identities issued here through standard token validation and JWKS-based signature verification.
- The system must behave as an OIDC-first identity platform, not as a custom ad hoc auth server.
- Multi-tenancy is a core feature, not an afterthought.

## Required Authentication Capabilities

The platform must support these first-factor sign-in methods:

- Google login
- Apple login
- Facebook login
- WeChat QR login
- Email login
- Username and password login
- Passkey-based passwordless login

The platform must support these MFA methods:

- Phone-based MFA
- TOTP-based MFA
- Passkey-based step-up authentication when appropriate

Each tenant must be able to enable or disable every login method and every MFA method independently.

Tenant configuration must also be able to express policy, not just on/off flags. Examples:

- whether username/password is allowed
- whether social login is allowed
- whether passkeys are allowed as primary sign-in, MFA, or both
- whether MFA is optional, recommended, or required
- which upstream social providers are enabled for the tenant

## Protocol Direction

Agents should design this system as a standards-first identity service.

Preferred protocol baseline:

- OpenID Connect 1.0
- OAuth 2.1 style authorization flows
- Authorization Code + PKCE as the default interactive sign-in flow
- Refresh tokens where appropriate
- Discovery metadata endpoint
- JWKS endpoint with key rotation support

Avoid inventing custom token flows when a standard OIDC or OAuth pattern already exists.

## Architecture Principles

### 1. Workers-native architecture

Cloudflare Workers is the only deployment target.

The codebase should still separate:

- domain logic
- protocol logic
- runtime adapters
- infrastructure adapters

Cloudflare-specific bindings should live in adapter and runtime layers, not inside identity domain code.

### 2. One Workers Hono application

The main HTTP surface should be implemented as a single Hono app for Cloudflare Workers.

Do not introduce parallel Node.js or self-hosted runtime codepaths.

### 3. Modular identity core

Keep the system split into focused modules with explicit boundaries. At minimum, expect separate modules for:

- tenants
- users and identities
- sessions and tokens
- OIDC/OAuth protocol endpoints
- upstream social identity providers
- MFA enrollment and challenge flows
- passkey and WebAuthn flows
- messaging adapters for email and phone delivery

### 4. Tenant-first modeling

Every security-sensitive record should be modeled with tenant scope in mind.

Tenant isolation applies to:

- enabled auth methods
- enabled MFA methods
- upstream provider configuration
- branding and redirect settings
- token issuer and client configuration where needed
- security policies and enrollment requirements

Do not add features that are globally configured if they should realistically vary by tenant.

## Initial Stack Guidance

Unless the user explicitly overrides these choices, prefer the following stack:

- Runtime language: TypeScript in strict mode
- HTTP framework: Hono
- Validation: Zod
- Token and JOSE handling: `jose`
- OIDC/OAuth helper logic: standards-oriented libraries, not opaque auth platforms
- WebAuthn: `@simplewebauthn/server` if runtime compatibility is acceptable
- Database: D1
- ORM and migrations: Drizzle ORM
- Test runner: Vitest
- Package manager: `pnpm`

## Storage and Infrastructure Defaults

Default persistence assumptions:

- D1 is the primary system of record.
- R2 stores private key material and object-style artifacts.
- KV stores sessions, short-lived registration tokens, caches, and other ephemeral state.
- Prefer Cloudflare-native services over cross-platform abstractions when there is no active self-hosted requirement.

The default persistence posture should favor correctness, operational simplicity on Workers, and clear data placement across D1, R2, and KV.

## Security Priorities

This is a security-sensitive codebase. Agents should optimize for correctness, auditability, and standards compliance before convenience.

Important priorities:

- secure session handling
- signed token issuance and validation
- key rotation readiness
- replay resistance where applicable
- secure password storage
- step-up authentication support
- careful redirect URI validation
- tenant-safe authorization boundaries
- explicit audit events for sensitive actions

Do not introduce weak crypto, homegrown signature formats, or custom password schemes.

## Product Interpretation Rules

When a requirement is ambiguous, use these defaults:

- "Email login" means passwordless email sign-in through magic link or one-time code unless the user specifies otherwise.
- "Username and password" is a separate credential-based sign-in path.
- "Phone-based MFA" means SMS or equivalent OTP delivery used as a second factor, not as the only default primary sign-in path.
- "Passkey login" means a first-class WebAuthn sign-in experience, not a decorative optional extra.
- Social login providers are upstream identity sources and should be implemented as pluggable adapters.

## Delivery Priorities

When planning implementation work, prioritize in this order:

1. Core tenant model and configuration model
2. OIDC foundation: issuer metadata, JWKS, token signing, client model
3. Authorization Code + PKCE flow
4. Local sign-in methods: username/password, email, passkey
5. MFA enrollment and challenge flows
6. Social login adapters: Google, Apple, Facebook, WeChat
7. Operational concerns: audit logs, rate limits, background jobs, admin APIs

## Agent Behavior Rules

When working in this repository:

- Treat Hono as mandatory, not optional.
- Treat TypeScript as mandatory, not optional.
- Prefer standards-based identity design over framework magic.
- Prefer Cloudflare-native infrastructure choices when they simplify the design.
- Keep Cloudflare-specific binding access in adapters and runtime entrypoints.
- Document material architecture decisions as the codebase grows.
- If a library is not compatible with Cloudflare Workers, do not adopt it by default.
- If a library assumes self-hosted Node.js or direct TCP/database drivers, do not adopt it by default.


## Short Decision Summary

This project is a Hono-based, TypeScript-only, multi-tenant identity provider.

Cloudflare Workers is the only runtime target.

D1, R2, and KV are the default platform services for persistence and state management.
