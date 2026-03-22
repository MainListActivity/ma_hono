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

Add five columns:

- `authenticated_user_id` — text, nullable — set to the tenant user's `id` after first-factor login succeeds; required so MFA endpoints can load the correct `totp_credentials` or `webauthn_credentials` without re-authenticating. Not set until first-factor passes, and not a FK constraint (to avoid coupling login challenge lifecycle to user deletion rules).
- `mfa_state` — text, not null, default `'none'`
  - `none` — no MFA required
  - `pending_totp` — first factor passed, awaiting TOTP code
  - `pending_passkey_step_up` — first factor passed, awaiting passkey step-up assertion
  - `pending_enrollment` — MFA required but user has no MFA enrolled; must enroll TOTP first
  - `satisfied` — MFA step completed
- `mfa_attempt_count` — integer, not null, default `0` — incremented on each failed TOTP verify or passkey step-up attempt; challenge is invalidated after 5 failures.
- `enrollment_attempt_count` — integer, not null, default `0` — incremented on each failed `enroll/finish` attempt; challenge is invalidated after 5 failures. Kept separate from `mfa_attempt_count` — see Security section for rationale.
- `totp_enrollment_secret_encrypted` — text, nullable — AES-256-GCM encrypted temporary TOTP secret held during `pending_enrollment` state; encrypted with the same key used for `totp_credentials.secret_encrypted`; cleared to null once enrollment succeeds.

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
| `last_used_window` | integer | Window index (`floor(unix_epoch_seconds / period)`) of last successfully accepted code; used for replay prevention. A code whose window index is ≤ `last_used_window` is rejected even if the HMAC matches. |
| `enrolled_at` | text | ISO timestamp |
| `created_at` | text | ISO timestamp |

Constraints:
- unique `(tenant_id, user_id)` — one active TOTP credential per user
- composite FK `(tenant_id, user_id)` → `(users.tenant_id, users.id)` with `onDelete: cascade` — consistent with the `userPasswordCredentials` and `webauthnCredentials` pattern in the existing schema

### `mfa_passkey_challenges` (new table)

Purpose: stores WebAuthn assertion challenge nonces for passkey step-up, using the same atomic-consume pattern as other one-time artifacts.

| Column | Type | Notes |
|---|---|---|
| `id` | text PK | |
| `tenant_id` | text FK → tenants | cascade delete |
| `login_challenge_id` | text | References the login challenge this nonce belongs to |
| `challenge_hash` | text | SHA-256 hash of the WebAuthn challenge nonce; used for lookup |
| `expires_at` | text | ISO timestamp — same expiry as the parent login challenge |
| `consumed_at` | text | nullable; set atomically on first successful `finish` call |
| `created_at` | text | ISO timestamp |

Constraints:
- unique `challenge_hash` where `consumed_at IS NULL`

The `finish` endpoint performs a conditional update `SET consumed_at = now WHERE challenge_hash = ? AND consumed_at IS NULL AND expires_at > now`. If zero rows are affected, the nonce is invalid, expired, or already consumed.

## Flow Design

### Post-First-Factor MFA Check

After any first-factor login succeeds (password, magic link, passkey login), before consuming the login challenge and issuing an authorization code:

1. Load `client_auth_method_policies.mfa_required` for the client on the login challenge.
2. If `mfa_required = false` — proceed as today: consume challenge, create browser session, redirect with authorization code.
3. If `mfa_required = true`:
   - Set `login_challenges.authenticated_user_id` to the verified user's `id`.
   - Check whether the user has a `totp_credentials` row or a `webauthn_credentials` row for this tenant.
   - If the user has passkey credential(s) → set `mfa_state = 'pending_passkey_step_up'`. If the user also has TOTP enrolled, the MFA UI must offer a "use authenticator app instead" option; selecting it calls a new `POST /api/login/:tenant/mfa/switch-to-totp` endpoint (see below) which transitions the challenge to `pending_totp`.
   - If the user has TOTP credential only → set `mfa_state = 'pending_totp'`.
   - If both passkey and TOTP are enrolled → default to `pending_passkey_step_up` with TOTP fallback available.
   - If neither → set `mfa_state = 'pending_enrollment'`.
   - Do NOT consume the login challenge. Return the current `mfa_state` and the `login_challenge` token to the browser.

### TOTP Verification

`POST /api/login/:tenant/mfa/totp/verify`

Request: `{ login_challenge: string, code: string }`

1. Load login challenge by token hash; verify it is unconsumed and not expired.
2. Verify `mfa_state = 'pending_totp'`.
3. Load `totp_credentials` WHERE `tenant_id = challenge.tenant_id` AND `user_id = challenge.authenticated_user_id`.
4. Decrypt the TOTP secret.
5. Compute the accepted window indices: `[floor(now/period) - 1, floor(now/period), floor(now/period) + 1]`.
6. Verify the provided code matches one of the accepted windows.
7. Check that the matched window index is strictly greater than `totp_credentials.last_used_window` (replay prevention).
8. On success:
   - Update `last_used_window` on the credential to the matched window index.
   - Update `mfa_state = 'satisfied'` on the challenge.
   - Consume the challenge, create browser session, issue authorization code, redirect.
9. On failure:
   - Increment `mfa_attempt_count` (verification counter, separate from enrollment counter — see Security section).
   - If `mfa_attempt_count >= 5` — mark challenge consumed (invalidated); return error telling user to restart.
   - Otherwise return error with remaining attempts.

### Passkey Step-Up

`POST /api/login/:tenant/mfa/passkey/start` — generates a WebAuthn assertion challenge scoped to the user's registered credentials (loaded via `login_challenges.authenticated_user_id`). The WebAuthn challenge nonce is stored in D1 in a `mfa_passkey_challenges` table (see Data Model below) with a `consumed_at` column, consistent with the existing atomic-consume pattern used for `login_challenges`, `authorization_codes`, and `email_login_tokens`. Returns the assertion options to the browser.

`POST /api/login/:tenant/mfa/passkey/finish` — verifies the assertion. Loads the `mfa_passkey_challenges` row by challenge hash, verifies it is unconsumed and not expired, then verifies the WebAuthn assertion. On success, marks the row consumed (atomic D1 update), updates `mfa_state = 'satisfied'`, consumes the login challenge, creates the browser session, and issues the authorization code.

Brute-force tracking: increment `mfa_attempt_count` only when the assertion is structurally valid (correct WebAuthn format) but the signature verification fails. Structurally invalid requests (missing fields, malformed CBOR, wrong content-type) return a `400` error without incrementing the counter to prevent denial-of-service via malformed payloads.

### Forced TOTP Enrollment Flow

Triggered when `mfa_state = 'pending_enrollment'`.

**Start:** `POST /api/login/:tenant/mfa/totp/enroll/start`

Request: `{ login_challenge: string }`

1. Verify challenge is unconsumed, not expired, and `mfa_state = 'pending_enrollment'`.
2. Generate a new TOTP secret (cryptographically random, base32-encoded).
3. If `totp_enrollment_secret_encrypted` is already set on the challenge (user called `enroll/start` again), overwrite it with the new secret. This is explicitly allowed — the old QR code is silently invalidated and a fresh one is issued. This is the correct behavior for "back / retry" navigation.
4. Encrypt the secret with AES-256-GCM and store it in `login_challenges.totp_enrollment_secret_encrypted`.
5. Return an `otpauth://` provisioning URI for display as a QR code, plus the raw secret for manual entry. The raw secret is returned only in this response and is never stored unencrypted.

**Finish:** `POST /api/login/:tenant/mfa/totp/enroll/finish`

Request: `{ login_challenge: string, code: string }`

1. Verify challenge is unconsumed, not expired, and `mfa_state = 'pending_enrollment'`.
2. Verify `totp_enrollment_secret_encrypted` is set; return error if not (user skipped `enroll/start`).
3. Decrypt `totp_enrollment_secret_encrypted` to obtain the enrollment secret.
4. Verify the provided TOTP code against the enrollment secret (same ±1 window logic as TOTP verification).
5. On success:
   - Insert a `totp_credentials` row WHERE `tenant_id = challenge.tenant_id` AND `user_id = challenge.authenticated_user_id`, with `secret_encrypted` reused from `totp_enrollment_secret_encrypted`, `last_used_window` set to the matched window index. If a unique constraint violation occurs (concurrent duplicate `enroll/finish` submissions), treat the insert as a success and skip the remaining steps (the first concurrent request will complete the consume and issue the authorization code). Do NOT attempt to consume the challenge again — return a generic success response indicating enrollment completed and login is in progress.
   - Clear `totp_enrollment_secret_encrypted` to null on the challenge.
   - Update `mfa_state = 'satisfied'`.
   - Consume the challenge, create browser session, issue authorization code, redirect.
6. On failure: increment `enrollment_attempt_count` (separate counter — see Security section); same brute-force lockout at 5 failures.

## API Endpoints

All paths follow the existing pattern: platform path includes `:tenant`, custom-domain path omits it.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/login/:tenant/mfa/totp/verify` | Verify TOTP code |
| `POST` | `/api/login/:tenant/mfa/passkey/start` | Start passkey step-up (stores WebAuthn nonce in D1 `mfa_passkey_challenges` with atomic-consume pattern) |
| `POST` | `/api/login/:tenant/mfa/passkey/finish` | Finish passkey step-up (atomically consumes nonce from D1 `mfa_passkey_challenges`, then verifies assertion) |
| `POST` | `/api/login/:tenant/mfa/switch-to-totp` | Transition challenge from `pending_passkey_step_up` to `pending_totp`. Validation: (1) challenge must be unconsumed and not expired; (2) `mfa_state` must be exactly `pending_passkey_step_up` — reject with `400` for any other state; (3) user must have a `totp_credentials` row (WHERE `tenant_id = challenge.tenant_id` AND `user_id = challenge.authenticated_user_id`) — reject with `400` if not enrolled. |
| `POST` | `/api/login/:tenant/mfa/totp/enroll/start` | Get TOTP provisioning URI |
| `POST` | `/api/login/:tenant/mfa/totp/enroll/finish` | Confirm enrollment and complete login |

## Security

### TOTP Secret Encryption

TOTP secrets are encrypted with AES-256-GCM before writing to D1. The encryption key is derived from key material in R2, consistent with the existing key infrastructure. The IV is stored alongside the ciphertext in the `secret_encrypted` field.

### Replay Prevention

`totp_credentials.last_used_window` stores the window index (`floor(unix_epoch_seconds / period)`) of the last successfully accepted code. A code whose window index is ≤ `last_used_window` is rejected even if the HMAC is correct. This is a precise per-bucket primitive: within a given 30-second bucket, only one acceptance is possible regardless of sub-second timing.

### Brute-Force Lockout

Two separate counters exist on `login_challenges`:

- `mfa_attempt_count` — incremented on each failure at the TOTP verify or passkey step-up endpoints. Represents failures by a user who claims to have MFA enrolled.
- `enrollment_attempt_count` — incremented on each failure at the `enroll/finish` endpoint. Separate because the enrollment path is structurally different: the user has no prior MFA commitment, and bundling these counters would let an attacker who knows a target has no MFA burn the single combined counter by driving them to enrollment.

Both counters trigger challenge invalidation at 5 failures.

Add `enrollment_attempt_count` integer column (not null, default `0`) to `login_challenges`.

### Enrollment Secret Lifecycle

The `totp_enrollment_secret_encrypted` column on `login_challenges` is ephemeral. It is stored AES-256-GCM encrypted (same key as `totp_credentials.secret_encrypted`). It is only populated during `pending_enrollment` state and cleared to null after successful enrollment. Multiple calls to `enroll/start` overwrite it with a new encrypted secret (idempotent replacement). If the challenge expires before enrollment completes, the encrypted secret is abandoned with the challenge — no orphaned TOTP secrets persist.

### Passkey Step-Up WebAuthn Nonce Storage

The WebAuthn assertion challenge nonce generated by `mfa/passkey/start` is stored in D1 in the `mfa_passkey_challenges` table (not KV) using the same atomic `consumed_at` pattern as all other one-time artifacts in this system. Cloudflare KV does not provide atomic read-and-delete, which would create a small concurrent-replay window. D1's conditional update (`SET consumed_at = now WHERE challenge_hash = ? AND consumed_at IS NULL`) prevents replay even under concurrent `finish` calls.

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

The `AuthMethodPolicyWire` TypeScript interface in `admin/src/api/client.ts` must be extended with `mfa_required: boolean`.

### API Change

The existing `PATCH /api/admin/clients/:clientId/auth-method-policy` endpoint accepts the new `mfa_required` boolean field alongside existing fields. No new endpoints are needed.

## Login Page UI (TenantLoginPage.tsx)

The end-user login page at `admin/src/pages/TenantLoginPage.tsx` must be updated to handle MFA step responses inline. This is a core part of the MFA feature — without it the login flow cannot complete.

### Current Behavior

Currently all login handlers (password, magic link, passkey) either redirect immediately (302/opaqueredirect) or return `{ redirect_uri }` on success.

### New Behavior

When a client requires MFA, the login endpoint responds with:

```json
{ "mfa_state": "pending_totp" | "pending_passkey_step_up" | "pending_enrollment", "login_challenge": "<token>" }
```

The page must detect this response (no redirect, body contains `mfa_state`) and switch to the appropriate MFA step view inline, without a page navigation.

### Page State Machine

Add a `mfaState` state variable alongside the existing `activeMethod`. When `mfaState` is non-null, the page renders the MFA step view instead of the login method tabs.

```
null (login methods) → "pending_totp" → verified → redirect
                     → "pending_passkey_step_up" → verified → redirect
                                                  → switch → "pending_totp"
                     → "pending_enrollment" → start (QR) → finish → redirect
```

### MFA Step Views

**`MfaTotpVerifyView`** — shown when `mfa_state = 'pending_totp'`
- 6-digit code input
- "Verify" button calls `POST /api/login/:tenant/mfa/totp/verify`
- On success: redirect to `redirect_uri`
- On failure: show remaining attempts; on lockout (challenge_invalidated) show restart message
- If user also has passkey (indicated by `mfa_methods` in response): show "Use passkey instead" link that calls `mfa/switch-to-passkey` — out of scope for now since switch-to-totp is the only defined switch; passkey → totp switch is in scope, totp → passkey is not

**`MfaPasskeyStepUpView`** — shown when `mfa_state = 'pending_passkey_step_up'`
- "Verify with Passkey" button calls `POST /api/login/:tenant/mfa/passkey/start`, then triggers `navigator.credentials.get`, then calls `POST /api/login/:tenant/mfa/passkey/finish`
- On success: redirect to `redirect_uri`
- On failure: show error; on lockout show restart message
- If user also has TOTP (indicated by `has_totp_fallback: true` in response): show "Use authenticator app instead" link that calls `POST /api/login/:tenant/mfa/switch-to-totp` and transitions page to `MfaTotpVerifyView`

**`MfaEnrollTotpView`** — shown when `mfa_state = 'pending_enrollment'`
- Two sub-steps:
  1. **Setup step**: calls `POST /api/login/:tenant/mfa/totp/enroll/start`, displays QR code (via a QR library or `<img src="otpauth://...">` rendered server-side, or a canvas-rendered QR), and the raw secret for manual entry
  2. **Confirm step**: 6-digit code input, calls `POST /api/login/:tenant/mfa/totp/enroll/finish`
- On enrollment success: redirect to `redirect_uri`
- On failure: show remaining attempts; on lockout show restart message

### `api/client.ts` New Functions

```ts
// After first-factor success with MFA required
type MfaRequiredResponse = {
  mfa_state: "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";
  login_challenge: string;
  has_totp_fallback?: boolean; // present when mfa_state = 'pending_passkey_step_up'
}

mfaTotpVerify(tenantSlug, loginChallenge, code): Promise<Response>
mfaPasskeyStart(tenantSlug, loginChallenge): Promise<{ challenge: string; allowed_credentials: ...; }>
mfaPasskeyFinish(tenantSlug, loginChallenge, credential): Promise<Response>
mfaSwitchToTotp(tenantSlug, loginChallenge): Promise<void>
mfaEnrollStart(tenantSlug, loginChallenge): Promise<{ provisioning_uri: string; secret: string }>
mfaEnrollFinish(tenantSlug, loginChallenge, code): Promise<Response>
```

### QR Code Rendering

Use a lightweight Workers-compatible QR library (e.g., `qrcode` npm package, browser-side rendering only). The raw `otpauth://` URI from `enroll/start` is rendered as a QR code in the browser. No server-side QR rendering required.

## Module Layout

```
src/
  domain/
    mfa/
      totp-service.ts                       — TOTP code generation and verification logic
      totp-repository.ts                    — TotpCredential repository interface
      mfa-passkey-challenge-repository.ts   — MfaPasskeyChallenge repository interface
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

### Login Page UI Tests

- After password login with MFA required: page renders TOTP verify view (not redirect)
- After passkey step-up start/finish: redirect occurs
- "Use authenticator app instead" link visible and functional when `has_totp_fallback = true`
- Enrollment QR code view renders, confirm step completes login
- Lockout message shown after 5 failures

## Delivery Sequence

1. Schema: add `mfa_required` to `client_auth_method_policies`; add `authenticated_user_id`, `mfa_state`, `mfa_attempt_count`, `enrollment_attempt_count`, `totp_enrollment_secret_encrypted` to `login_challenges`; add `totp_credentials` table with composite FK; add `mfa_passkey_challenges` table
2. `domain/mfa/totp-service.ts`: TOTP code generation, window-index verification, replay check
3. `adapters/auth/totp/totp-crypto.ts`: AES-256-GCM encrypt/decrypt for TOTP secrets
4. `domain/mfa/totp-repository.ts` + memory implementation
5. Post-first-factor MFA check integrated into existing login handlers (steps 5 and 6 can proceed in parallel after step 4 since both depend only on schema and domain layer being in place)
6. MFA API endpoints: TOTP verify, passkey step-up start/finish, TOTP fallback switch, enrollment start/finish
7. Audit events for all MFA actions
8. Admin API: extend PATCH endpoint to accept `mfa_required`; extend `AuthMethodPolicyWire` in `admin/src/api/client.ts`
9. Admin UI: add `mfa_required` toggle to client detail page
10. Login page UI: add MFA state detection in login handlers + `MfaTotpVerifyView`, `MfaPasskeyStepUpView`, `MfaEnrollTotpView` components + new API functions in `api/client.ts`
11. Tests

## Acceptance Criteria

- A client with `mfa_required = true` causes password/magic-link/passkey login to pause pending MFA
- A user with TOTP enrolled can complete login by providing a valid TOTP code
- A user with passkey enrolled can complete login via passkey step-up
- A user with both passkey and TOTP enrolled is defaulted to `pending_passkey_step_up` and can switch to TOTP via `mfa/switch-to-totp`
- A user with passkey enrolled but no TOTP enrolled cannot call `mfa/switch-to-totp` (returns `400`)
- A user with no MFA enrolled is forced through TOTP enrollment before login completes
- TOTP codes cannot be reused within the same 30-second window (window-index replay prevention)
- 5 consecutive MFA verification failures invalidate the login challenge
- 5 consecutive enrollment confirmation failures invalidate the login challenge
- A client with `mfa_required = false` is unaffected by this change
- Admin can toggle `mfa_required` on the client detail page
- All MFA events are recorded in `audit_events`
- After password/magic-link/passkey login where MFA is required, the login page transitions to the correct MFA step view inline (no page navigation)
- TOTP enrollment QR code is displayed and user can complete enrollment to finish login
- Passkey step-up UI completes the MFA step
- "Use authenticator app instead" is available when user has both passkey and TOTP enrolled
