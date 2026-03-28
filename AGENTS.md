# AGENTS.md

## Project Structure
- src: Hono backend, domains `auth.{domain}/api*` and `o.{domain}*`
- admin: UI — Tenant Login, Admin Login, User Info, MFA pages, domain `auth.{domain}/*`
- test: tests
- drizzle/migrations: DDL migrations, apply via `db:migrate:remote`
- docs: documentation

## Purpose

Multi-tenant identity provider (IdP) and authentication backend. OIDC-first. End users sign in here; relying applications verify identity via discovery metadata, signed tokens, and JWKS.

## Locked Stack

- **Language:** TypeScript (strict mode)
- **Framework:** Hono (mandatory)
- **Runtime:** Cloudflare Workers only
- **Storage:** D1 (primary DB), R2 (key material), KV (sessions/cache/ephemeral state)
- **ORM:** Drizzle ORM
- **Validation:** Zod
- **JOSE:** `jose`
- **WebAuthn:** `@simplewebauthn/server`
- **Tests:** Vitest
- **Package manager:** pnpm

Do not adopt libraries incompatible with Cloudflare Workers or requiring Node.js TCP/database drivers.

## Authentication Methods

First-factor: Google, Apple, Facebook, WeChat QR, Email (magic link/OTP), Username+Password, Passkey (WebAuthn).

MFA: Phone OTP, TOTP, Passkey step-up.

Each tenant independently enables/disables methods and configures policy (MFA optional/recommended/required, allowed providers, passkey as primary/MFA/both).

## Protocol

- OpenID Connect 1.0 / OAuth 2.1
- Authorization Code + PKCE as default flow
- Discovery metadata + JWKS with key rotation
- Refresh tokens where appropriate
- No custom token flows when a standard exists

## Architecture

1. **Single Hono app** on Cloudflare Workers. No parallel Node.js codepaths.
2. **Separation of concerns:** domain logic / protocol logic / runtime adapters / infrastructure adapters. CF bindings stay in adapter layers.
3. **Modular core:** tenants, users/identities, sessions/tokens, OIDC endpoints, social providers, MFA flows, WebAuthn, messaging adapters.
4. **Tenant-first:** every security-sensitive record is tenant-scoped. Auth methods, MFA, providers, branding, issuers, policies — all per-tenant.

## Security

Optimize for correctness, auditability, and standards compliance.

- Secure session handling and password storage
- Signed token issuance/validation with key rotation
- Replay resistance, redirect URI validation
- Tenant-safe authorization boundaries
- Audit events for sensitive actions
- No weak crypto, homegrown signatures, or custom password schemes

## Interpretation Defaults

- "Email login" = passwordless (magic link/OTP), not password-based
- "Passkey login" = first-class WebAuthn, not optional extra
- "Phone MFA" = SMS/OTP second factor, not primary sign-in
- Social providers = pluggable upstream adapters

## Delivery Priority

1. Tenant model + configuration
2. OIDC foundation (issuer, JWKS, token signing, client model)
3. Authorization Code + PKCE
4. Local sign-in (username/password, email, passkey)
5. MFA flows
6. Social login adapters
7. Operational (audit, rate limits, admin APIs)
