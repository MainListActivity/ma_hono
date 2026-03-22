# TOTP and MFA Design

## Goal

Add TOTP-based MFA and passkey step-up as a second factor to the login flow. MFA enforcement is configured per OIDC client. When a client requires MFA, first-factor login pauses until the user completes a second factor. Users without any MFA enrolled are forced through inline TOTP enrollment before login completes.

## Scope

### In Scope

- `mfa_required` policy flag on `client_auth_method_policies`
- Login challenge MFA state machine (`none`, `pending_totp`, `pending_passkey_step_up`, `pending_enrollment`, `satisfied`)
- TOTP credential enrollment (forced inline during login when MFA is required)
- TOTP code verification with replay protection and brute-force lockout
- Passkey step-up as an alternative second factor (reuses existing `webauthn_credentials`)
- New MFA API endpoints under `/api/login/:tenant/mfa/*`
- Admin UI: `mfa_required` toggle on the client detail page auth method policy section
- Audit events for MFA verification, enrollment, and brute-force invalidation

### Out of Scope

- Voluntary TOTP enrollment from an account settings page (separate future feature)
- SMS/phone MFA
- Admin-managed TOTP revocation
- Per-user MFA policy override
- Recovery codes

## Product Constraints

- TypeScript only
- Hono only for the HTTP layer
- Cloudflare Workers only
- D1, KV, R2 for storage
- Multi-tenant, client-scoped MFA policy

## Data Model

### `client_auth_method_policies` Extension

Add one column:

- `mfa_required` — boolean, not null, default `false`

### `login_challenges` Extension

Add three columns:

- `mfa_state` — text, not null, default `'none'`
  - `none` — no MFA required
  - `pending_totp` — awaiting TOTP code
  - `pending_passkey_step_up` — awaiting passkey step-up assertion
  - `pending_enrollment` — MFA required but user has no MFA enrolled; must enroll TOTP first
  - `satisfied` — MFA step completed
- `mfa_attempt_count` — integer, not null, default `0` — incremented on each failed MFA attempt; challenge is invalidated after 5 failures
- `totp_enrollment_secret` — text, nullable — temporary TOTP secret held during `pending_enrollment` state; cleared to null once enrollment succeeds

The challenge is consumable only when `mfa_state IN ('none', 'satisfied')`.

### `totp_credentials` (new table)

Purpose: stores enrolled TOTP secrets per tenant user.

| Column | Type | Notes |
|---|---|---|
| `id` | text PK | |
| `tenant_id` | text FK → tenants | cascade delete |
| `user_id` | text FK → users | cascade delete |
| `secret_encrypted` | text | AES-256-GCM encrypted TOTP secret |
| `algorithm` | text | `SHA1` |
| `digits` | integer | `6` |
| `period` | integer | `30` |
| `last_used_at` | text | ISO timestamp of last successful verification; used for replay prevention |
| `enrolled_at` | text | ISO timestamp |
| `created_at` | text | ISO timestamp |

Constraints:
- unique `(tenant_id, user_id)` — one active TOTP credential per user

## Flow Design

### Post-First-Factor MFA Check

After any first-factor login succeeds (password, magic link, passkey login), before consuming the login challenge and issuing an authorization code:

1. Load `client_auth_method_policies.mfa_required` for the client on the login challenge.
2. If `mfa_required = false` — proceed as today: consume challenge, create browser session, redirect with authorization code.
3. If `mfa_required = true`:
   - Check whether the user has a `totp_credentials` row or a `webauthn_credentials` row for this tenant.
   - If the user has passkey credential(s) → set `mfa_state = 'pending_passkey_step_up'`.
   - If the user has TOTP credential only → set `mfa_state = 'pending_totp'`.
   - If both → prefer passkey step-up (set `pending_passkey_step_up`); the MFA UI may also allow TOTP as fallback.
   - If neither → set `mfa_state = 'pending_enrollment'`.
   - Do NOT consume the login challenge. Return the current `mfa_state` and the `login_challenge` token to the browser.

### TOTP Verification

`POST /api/login/:tenant/mfa/totp/verify`

Request: `{ login_challenge: string, code: string }`

1. Load login challenge by token hash; verify it is unconsumed and not expired.
2. Verify `mfa_state = 'pending_totp'`.
3. Load `totp_credentials` for the challenge's user.
4. Decrypt the TOTP secret.
5. Verify the provided code with ±1 window tolerance (90-second window).
6. Check that the current window timestamp is strictly after `last_used_at` (replay prevention).
7. On success:
   - Update `last_used_at` on the credential.
   - Update `mfa_state = 'satisfied'` on the challenge.
   - Consume the challenge, create browser session, issue authorization code, redirect.
8. On failure:
   - Increment `mfa_attempt_count`.
   - If `mfa_attempt_count >= 5` — mark challenge consumed (invalidated); return error telling user to restart.
   - Otherwise return error with remaining attempts.

### Passkey Step-Up

`POST /api/login/:tenant/mfa/passkey/start` — generates a WebAuthn assertion challenge scoped to the user's registered credentials.

`POST /api/login/:tenant/mfa/passkey/finish` — verifies the assertion.

On success: update `mfa_state = 'satisfied'`, consume challenge, create session, issue code.

Brute-force tracking applies the same `mfa_attempt_count` logic.

### Forced TOTP Enrollment Flow

Triggered when `mfa_state = 'pending_enrollment'`.

**Start:** `POST /api/login/:tenant/mfa/totp/enroll/start`

Request: `{ login_challenge: string }`

1. Verify challenge is unconsumed, not expired, and `mfa_state = 'pending_enrollment'`.
2. Generate a new TOTP secret (cryptographically random, base32-encoded).
3. Store the raw secret temporarily in `login_challenges.totp_enrollment_secret` (not yet encrypted into `totp_credentials`).
4. Return a `otpauth://` provisioning URI for display as a QR code, plus the raw secret for manual entry.

**Finish:** `POST /api/login/:tenant/mfa/totp/enroll/finish`

Request: `{ login_challenge: string, code: string }`

1. Verify challenge is unconsumed, not expired, and `mfa_state = 'pending_enrollment'`.
2. Read `totp_enrollment_secret` from the challenge.
3. Verify the provided TOTP code against the enrollment secret.
4. On success:
   - Encrypt the secret with AES-256-GCM.
   - Insert a `totp_credentials` row.
   - Clear `totp_enrollment_secret` to null on the challenge.
   - Update `mfa_state = 'satisfied'`.
   - Consume the challenge, create browser session, issue authorization code, redirect.
5. On failure: increment `mfa_attempt_count`; same brute-force rules as verification.

## API Endpoints

All paths follow the existing pattern: platform path includes `:tenant`, custom-domain path omits it.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/login/:tenant/mfa/totp/verify` | Verify TOTP code |
| `POST` | `/api/login/:tenant/mfa/passkey/start` | Start passkey step-up |
| `POST` | `/api/login/:tenant/mfa/passkey/finish` | Finish passkey step-up |
| `POST` | `/api/login/:tenant/mfa/totp/enroll/start` | Get TOTP provisioning URI |
| `POST` | `/api/login/:tenant/mfa/totp/enroll/finish` | Confirm enrollment and complete login |

## Security

### TOTP Secret Encryption

TOTP secrets are encrypted with AES-256-GCM before writing to D1. The encryption key is derived from key material in R2, consistent with the existing key infrastructure. The IV is stored alongside the ciphertext in the `secret_encrypted` field.

### Replay Prevention

`totp_credentials.last_used_at` records the timestamp of the last successfully accepted window. A code is rejected if the window it covers is not strictly after `last_used_at`.

### Brute-Force Lockout

`login_challenges.mfa_attempt_count` is incremented on each MFA failure. At 5 failures the challenge is marked consumed and the user must restart the authorization flow from the client. This prevents code enumeration without requiring a separate rate-limit layer.

### Enrollment Secret Lifecycle

The `totp_enrollment_secret` column on `login_challenges` is ephemeral. It is only populated during `pending_enrollment` state and cleared to null after successful enrollment. If the challenge expires before enrollment completes, the secret is abandoned with the challenge — no orphaned TOTP secrets can persist.

## Audit Events

| Event Type | When |
|---|---|
| `mfa.totp.verified` | Successful TOTP code verification |
| `mfa.totp.failed` | Failed TOTP code attempt |
| `mfa.totp.enrolled` | TOTP enrollment completed |
| `mfa.passkey_stepup.verified` | Passkey step-up assertion verified |
| `mfa.passkey_stepup.failed` | Passkey step-up assertion failed |
| `mfa.challenge.invalidated` | Login challenge killed due to brute-force lockout |

## Admin UI

### Client Detail Page — Auth Method Policy Section

The existing auth method policy card on the client detail page in `admin/` gets one new field:

- **Require MFA** — boolean toggle, default off
- When enabled, display an informational note: users without MFA enrolled will be prompted to enroll on their next login to this client

### API Change

The existing `PATCH /api/admin/clients/:clientId/auth-method-policy` endpoint accepts the new `mfa_required` boolean field alongside existing fields. No new endpoints are needed.

## Module Layout

```
src/
  domain/
    mfa/
      totp-service.ts           — TOTP code generation and verification logic
      totp-repository.ts        — TotpCredential repository interface
  adapters/
    auth/
      totp/
        totp-crypto.ts          — AES-256-GCM encrypt/decrypt for TOTP secrets
    db/
      drizzle/
        schema.ts               — extended with totp_credentials table and new columns
      memory/
        memory-totp-repository.ts
```

## Testing Strategy

### Unit Tests

- TOTP code generation and verification (correct window, ±1 tolerance, replay rejection)
- AES-256-GCM encrypt/decrypt round-trip for TOTP secrets
- Login challenge MFA state transitions
- Brute-force lockout at attempt threshold

### Integration Tests

- Password login with `mfa_required = true` and TOTP enrolled: challenge pauses, TOTP verify completes flow
- Password login with `mfa_required = true` and no MFA enrolled: forced enrollment flow completes login
- Password login with `mfa_required = false`: flow unchanged
- Passkey step-up: start/finish completes the MFA step
- Brute-force: 5 failures invalidate the challenge
- Replay: reusing same TOTP code in same window is rejected

### Admin UI Tests

- `mfa_required` toggle persists correctly via PATCH
- Toggling on and off reflects correctly on reload

## Delivery Sequence

1. Schema: add `mfa_required` to `client_auth_method_policies`, add `mfa_state`/`mfa_attempt_count`/`totp_enrollment_secret` to `login_challenges`, add `totp_credentials` table
2. `domain/mfa/totp-service.ts`: TOTP code generation, verification, window logic, replay check
3. `adapters/auth/totp/totp-crypto.ts`: AES-256-GCM secret encryption/decryption
4. `domain/mfa/totp-repository.ts` + memory implementation
5. Post-first-factor MFA check integrated into existing login handlers
6. MFA API endpoints: TOTP verify, passkey step-up start/finish, enrollment start/finish
7. Audit events for all MFA actions
8. Admin API: extend PATCH endpoint to accept `mfa_required`
9. Admin UI: add `mfa_required` toggle to client detail page
10. Tests

## Acceptance Criteria

- A client with `mfa_required = true` causes password/magic-link/passkey login to pause pending MFA
- A user with TOTP enrolled can complete login by providing a valid TOTP code
- A user with passkey enrolled can complete login via passkey step-up
- A user with no MFA enrolled is forced through TOTP enrollment before login completes
- TOTP codes cannot be reused within the same 30-second window
- 5 consecutive MFA failures invalidate the login challenge
- A client with `mfa_required = false` is unaffected by this change
- Admin can toggle `mfa_required` on the client detail page
- All MFA events are recorded in `audit_events`
