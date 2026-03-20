# AGENTS.md

## Purpose

This repository will become a multi-tenant identity provider (IdP) and authentication backend.

End users sign in to this service. Other applications trust the authenticated user through standards-based identity protocols exposed by this service, especially OpenID Connect discovery metadata, signed tokens, and a published JWKS endpoint.

This document defines the default context, architectural constraints, and decision rules for AI coding agents working in this repository.

## Locked Technology Decisions

- Use TypeScript only.
- Use Hono only for the HTTP application layer.
- Target Cloudflare Workers first.
- Support self-hosted cloud deployment with the same Hono application and shared domain modules.

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

### 1. Workers-first, but not Workers-locked

Cloudflare Workers is the primary deployment target.

However, core business logic must not depend directly on Cloudflare-only runtime APIs. The codebase should separate:

- domain logic
- protocol logic
- runtime adapters
- infrastructure adapters

Cloudflare-specific bindings should live in adapter layers, not inside identity domain code.

### 2. One portable Hono application

The main HTTP surface should be implemented as a Hono app that can run:

- on Cloudflare Workers
- in a self-hosted Node.js environment

Do not fork the application into separate edge and self-hosted codepaths unless there is a proven technical need.

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
- Database: PostgreSQL
- ORM and migrations: Drizzle ORM
- Test runner: Vitest
- Package manager: `pnpm`

## Storage and Infrastructure Defaults

Default persistence assumptions:

- PostgreSQL is the primary system of record.
- Design database access so it works in both Cloudflare-first and self-hosted deployments.
- Prefer infrastructure choices that have a clear Cloudflare Workers path and a clear self-hosted path.

Do not hard-couple the system to Cloudflare D1, KV, Durable Objects, or Queues unless a concrete requirement justifies it. These can be added behind adapters when necessary.

The default persistence posture should favor portability and correctness over maximum platform-specific optimization.

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
- Treat Rust as out of scope.
- Prefer standards-based identity design over framework magic.
- Prefer portable abstractions over platform lock-in.
- Keep Cloudflare-specific code at the edge of the system.
- Document material architecture decisions as the codebase grows.
- If a library is not compatible with Cloudflare Workers, do not adopt it by default.
- If a library is self-host-only, use it only behind an adapter and only when there is a strong reason.

## Non-Goals

The following are not default goals unless the user later asks for them:

- building a generic consumer IAM platform for every enterprise use case on day one
- supporting every OAuth grant type immediately
- coupling relying-party trust to custom proprietary auth contracts
- optimizing prematurely for Rust, native binaries, or non-Hono runtimes

## Short Decision Summary

This project is a Hono-based, TypeScript-only, multi-tenant identity provider.

Cloudflare Workers is the primary runtime target.

Self-hosted deployment is required, but it should be achieved through portable architecture and adapters, not by abandoning Hono or reintroducing Rust.
