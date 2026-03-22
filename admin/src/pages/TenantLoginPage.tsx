import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import {
  type ChallengeInfo,
  consumeMagicLink,
  getChallengeInfo,
  loginWithPassword,
  mfaEnrollFinish,
  mfaEnrollStart,
  mfaPasskeyFinish,
  mfaPasskeyStart,
  mfaSwitchToTotp,
  mfaTotpVerify,
  registerUser,
  requestMagicLink
} from "../api/client";

type MfaState = "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";

// ─── Shared visual primitives ─────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: "100%",
  background: "var(--bg-base)",
  border: "1px solid var(--border)",
  color: "var(--text-primary)",
  padding: "8px 12px",
  fontSize: "13px",
  fontFamily: "'IBM Plex Sans', sans-serif",
  outline: "none",
  boxSizing: "border-box",
  transition: "border-color 0.15s"
};

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "10px",
  letterSpacing: "0.12em",
  textTransform: "uppercase" as const,
  color: "var(--text-muted)",
  marginBottom: "6px"
};

const primaryButtonStyle = (disabled: boolean): React.CSSProperties => ({
  width: "100%",
  background: disabled ? "var(--bg-elevated)" : "transparent",
  border: "1px solid var(--accent-cyan)",
  color: disabled ? "var(--text-muted)" : "var(--accent-cyan)",
  padding: "10px",
  fontSize: "11px",
  fontFamily: "'Space Mono', monospace",
  letterSpacing: "0.15em",
  textTransform: "uppercase" as const,
  cursor: disabled ? "not-allowed" : "pointer",
  transition: "all 0.15s",
  boxShadow: disabled ? "none" : "0 0 12px rgba(0,229,255,0.1)"
});

const tabButtonStyle = (active: boolean): React.CSSProperties => ({
  flex: 1,
  background: active ? "rgba(0,229,255,0.08)" : "transparent",
  border: "none",
  borderBottom: active ? "1px solid var(--accent-cyan)" : "1px solid var(--border)",
  color: active ? "var(--accent-cyan)" : "var(--text-muted)",
  padding: "10px 8px",
  fontSize: "10px",
  fontFamily: "'Space Mono', monospace",
  letterSpacing: "0.12em",
  textTransform: "uppercase" as const,
  cursor: "pointer",
  transition: "all 0.15s"
});

// ─── Method tabs ───────────────────────────────────────────────────────────────

const METHOD_LABELS: Record<string, string> = {
  password: "Password",
  magic_link: "Magic Link",
  passkey: "Passkey"
};

// ─── Sub-forms ─────────────────────────────────────────────────────────────────

function RegisterForm({
  tenantSlug,
  loginChallenge,
  onBackToSignIn
}: {
  tenantSlug: string;
  loginChallenge: string;
  onBackToSignIn: () => void;
}) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      const res = await registerUser(tenantSlug, {
        login_challenge: loginChallenge,
        email,
        ...(username.trim() ? { username: username.trim() } : {}),
        password
      });
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) { window.location.href = location; return; }
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        if (body.error === "email_already_exists") {
          setError("An account with this email already exists. Please sign in.");
        } else {
          setError(body.error ?? "Registration failed");
        }
        return;
      }
    } catch {
      setError("Network error — please try again");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 12px", border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.05)" }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>✕ {error}</span>
        </div>
      )}
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Email</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Username (optional)</label>
        <input type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "14px" }}>
        <label className="font-display" style={labelStyle}>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="new-password"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <div style={{ marginBottom: "20px" }}>
        <label className="font-display" style={labelStyle}>Confirm Password</label>
        <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required autoComplete="new-password"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)}>
        {loading ? "Creating account..." : "Create Account"}
      </button>
      <div style={{ textAlign: "center", marginTop: "16px" }}>
        <button type="button" onClick={onBackToSignIn}
          style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
          Back to sign in
        </button>
      </div>
    </form>
  );
}

function PasswordForm({
  tenantSlug,
  loginChallenge,
  allowRegistration,
  onMfaRequired
}: {
  tenantSlug: string;
  loginChallenge: string;
  allowRegistration: boolean;
  onMfaRequired: (ctx: { mfaState: MfaState; loginChallenge: string; hasTotpFallback: boolean }) => void;
}) {
  const [showRegister, setShowRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await loginWithPassword(tenantSlug, loginChallenge, username, password);
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) {
          window.location.href = location;
          return;
        }
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? "Login failed");
        return;
      }
      const body = await res.json().catch(() => ({})) as {
        redirect_uri?: string;
        mfa_state?: string;
        login_challenge?: string;
        has_totp_fallback?: boolean;
      };
      if (body.mfa_state && body.login_challenge) {
        onMfaRequired({
          mfaState: body.mfa_state as MfaState,
          loginChallenge: body.login_challenge,
          hasTotpFallback: body.has_totp_fallback ?? false
        });
        return;
      }
      if (body.redirect_uri) window.location.href = body.redirect_uri;
    } catch {
      setError("Network error — please try again");
    } finally {
      setLoading(false);
    }
  };

  if (showRegister) {
    return (
      <RegisterForm
        tenantSlug={tenantSlug}
        loginChallenge={loginChallenge}
        onBackToSignIn={() => setShowRegister(false)}
      />
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div style={{
          marginBottom: "16px",
          padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)",
          background: "rgba(239,68,68,0.05)"
        }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>
            ✕ {error}
          </span>
        </div>
      )}
      <div style={{ marginBottom: "16px" }}>
        <label className="font-display" style={labelStyle}>Username or Email</label>
        <input
          type="text"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
          autoComplete="username"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")}
        />
      </div>
      <div style={{ marginBottom: "24px" }}>
        <label className="font-display" style={labelStyle}>Password</label>
        <input
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")}
        />
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)}>
        {loading ? "Signing in..." : "Sign In"}
      </button>
      {allowRegistration && (
        <div style={{ textAlign: "center", marginTop: "16px" }}>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            Don't have an account?{" "}
            <button type="button" onClick={() => setShowRegister(true)}
              style={{ background: "none", border: "none", color: "var(--accent-cyan)", fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
              Register
            </button>
          </span>
        </div>
      )}
    </form>
  );
}

function MagicLinkForm({
  tenantSlug,
  loginChallenge
}: {
  tenantSlug: string;
  loginChallenge: string;
}) {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await requestMagicLink(tenantSlug, loginChallenge, email);
      setSent(true);
    } catch {
      setError("Failed to send magic link — please try again");
    } finally {
      setLoading(false);
    }
  };

  if (sent) {
    return (
      <div style={{ textAlign: "center", padding: "24px 0" }}>
        <div style={{ fontSize: "24px", marginBottom: "16px" }}>✉</div>
        <p className="font-display" style={{ fontSize: "11px", color: "var(--text-muted)", letterSpacing: "0.08em" }}>
          CHECK YOUR EMAIL
        </p>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "8px" }}>
          A sign-in link has been sent to <strong>{email}</strong>. Click the link in the email to continue.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div style={{
          marginBottom: "16px",
          padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)",
          background: "rgba(239,68,68,0.05)"
        }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>
            ✕ {error}
          </span>
        </div>
      )}
      <div style={{ marginBottom: "24px" }}>
        <label className="font-display" style={labelStyle}>Email Address</label>
        <input
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          autoComplete="email"
          placeholder="you@example.com"
          style={{ ...inputStyle, color: email ? "var(--text-primary)" : "var(--text-muted)" }}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")}
        />
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)}>
        {loading ? "Sending..." : "Send Magic Link"}
      </button>
    </form>
  );
}

function PasskeyForm({
  tenantSlug,
  loginChallenge,
  onMfaRequired
}: {
  tenantSlug: string;
  loginChallenge: string;
  onMfaRequired: (ctx: { mfaState: MfaState; loginChallenge: string; hasTotpFallback: boolean }) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handlePasskeyLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      const { startPasskeyLogin, finishPasskeyLogin } = await import("../api/client");
      const startResult = await startPasskeyLogin(tenantSlug, loginChallenge) as {
        assertion_session_id: string;
        challenge: string;
      };

      const challengeBytes = Uint8Array.from(
        atob(startResult.challenge.replace(/-/g, "+").replace(/_/g, "/")),
        c => c.charCodeAt(0)
      );
      const credential = await navigator.credentials.get({
        publicKey: { challenge: challengeBytes, timeout: 60000, userVerification: "preferred" }
      }) as PublicKeyCredential | null;

      if (!credential) {
        setError("No passkey was selected");
        return;
      }

      const res = await finishPasskeyLogin(tenantSlug, startResult.assertion_session_id, credential);
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) { window.location.href = location; return; }
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? "Passkey authentication failed");
        return;
      }
      const body = await res.json().catch(() => ({})) as {
        redirect_uri?: string;
        mfa_state?: string;
        login_challenge?: string;
        has_totp_fallback?: boolean;
      };
      if (body.mfa_state && body.login_challenge) {
        onMfaRequired({
          mfaState: body.mfa_state as MfaState,
          loginChallenge: body.login_challenge,
          hasTotpFallback: body.has_totp_fallback ?? false
        });
        return;
      }
      if (body.redirect_uri) window.location.href = body.redirect_uri;
    } catch (err) {
      if (err instanceof Error && err.name === "NotAllowedError") {
        setError("Passkey prompt was cancelled");
      } else {
        setError("Passkey authentication failed — please try again");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {error && (
        <div style={{
          marginBottom: "16px",
          padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)",
          background: "rgba(239,68,68,0.05)"
        }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>
            ✕ {error}
          </span>
        </div>
      )}
      <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "24px" }}>
        Use a passkey stored on this device or a security key to sign in.
      </p>
      <button
        type="button"
        disabled={loading}
        onClick={handlePasskeyLogin}
        style={primaryButtonStyle(loading)}
      >
        {loading ? "Waiting for passkey..." : "Sign In with Passkey"}
      </button>
    </div>
  );
}

// ─── MFA view components ──────────────────────────────────────────────────────

function MfaTotpVerifyView({
  tenantSlug, loginChallenge
}: {
  tenantSlug: string; loginChallenge: string;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await mfaTotpVerify(tenantSlug, loginChallenge, code);
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) { window.location.href = location; return; }
      }
      const body = await res.json().catch(() => ({})) as {
        error?: string; remaining_attempts?: number; redirect_uri?: string
      };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("Too many failed attempts. Please return to the application and try again.");
      } else {
        setError(`Invalid code${body.remaining_attempts !== undefined ? ` — ${body.remaining_attempts} attempts remaining` : ""}`);
      }
    } catch { setError("Network error — please try again"); }
    finally { setLoading(false); }
  };

  return (
    <form onSubmit={handleVerify}>
      <div className="font-display" style={{ fontSize: "10px", letterSpacing: "0.12em",
        textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "16px" }}>
        TWO-FACTOR VERIFICATION
      </div>
      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.05)" }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>
            ✕ {error}
          </span>
        </div>
      )}
      <div style={{ marginBottom: "24px" }}>
        <label className="font-display" style={labelStyle}>Authenticator Code</label>
        <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
          value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
          required autoComplete="one-time-code"
          placeholder="000000"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <button type="submit" disabled={loading || code.length !== 6} style={primaryButtonStyle(loading || code.length !== 6)}>
        {loading ? "Verifying..." : "Verify"}
      </button>
    </form>
  );
}

function MfaPasskeyStepUpView({
  tenantSlug, loginChallenge, hasTotpFallback, onSwitchToTotp
}: {
  tenantSlug: string; loginChallenge: string; hasTotpFallback: boolean;
  onSwitchToTotp: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleStepUp = async () => {
    setError(null); setLoading(true);
    try {
      const startResult = await mfaPasskeyStart(tenantSlug, loginChallenge);
      const challengeBytes = Uint8Array.from(
        atob(startResult.challenge.replace(/-/g, "+").replace(/_/g, "/")),
        c => c.charCodeAt(0)
      );
      const credential = await navigator.credentials.get({
        publicKey: { challenge: challengeBytes, timeout: 60000, userVerification: "required" }
      }) as PublicKeyCredential | null;
      if (!credential) { setError("No passkey selected"); return; }
      // Pass the raw nonce; mfaPasskeyFinish will SHA-256 hash it before sending to the server
      const res = await mfaPasskeyFinish(tenantSlug, loginChallenge, startResult.challenge, credential);
      if (res.status === 302 || res.type === "opaqueredirect") {
        const loc = res.headers.get("location");
        if (loc) { window.location.href = loc; return; }
      }
      const body = await res.json().catch(() => ({})) as { error?: string; redirect_uri?: string };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("Too many failed attempts. Please return to the application and try again.");
      } else {
        setError("Passkey verification failed — please try again");
      }
    } catch (err) {
      if (err instanceof Error && err.name === "NotAllowedError") setError("Passkey prompt cancelled");
      else setError("Passkey verification failed — please try again");
    } finally { setLoading(false); }
  };

  return (
    <div>
      <div className="font-display" style={{ fontSize: "10px", letterSpacing: "0.12em",
        textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "16px" }}>
        PASSKEY VERIFICATION
      </div>
      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.05)" }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>✕ {error}</span>
        </div>
      )}
      <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "24px" }}>
        Use your registered passkey to complete sign-in.
      </p>
      <button type="button" disabled={loading} onClick={handleStepUp} style={primaryButtonStyle(loading)}>
        {loading ? "Waiting for passkey..." : "Verify with Passkey"}
      </button>
      {hasTotpFallback && (
        <div style={{ textAlign: "center", marginTop: "16px" }}>
          <button type="button" onClick={onSwitchToTotp}
            style={{ background: "none", border: "none", color: "var(--text-muted)",
              fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
            Use authenticator app instead
          </button>
        </div>
      )}
    </div>
  );
}

function MfaEnrollTotpView({
  tenantSlug, loginChallenge
}: {
  tenantSlug: string; loginChallenge: string;
}) {
  const [step, setStep] = useState<"loading" | "setup" | "confirm">("loading");
  const [secret, setSecret] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    mfaEnrollStart(tenantSlug, loginChallenge)
      .then(async ({ provisioning_uri, secret: rawSecret }) => {
        setSecret(rawSecret);
        // Render QR code using qrcode package
        const QRCode = await import("qrcode");
        const dataUrl = await QRCode.toDataURL(provisioning_uri);
        setQrDataUrl(dataUrl);
        setStep("setup");
      })
      .catch(() => setError("Failed to start enrollment — please try again"));
  }, [tenantSlug, loginChallenge]);

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setLoading(true);
    try {
      const res = await mfaEnrollFinish(tenantSlug, loginChallenge, code);
      if (res.status === 302 || res.type === "opaqueredirect") {
        const loc = res.headers.get("location");
        if (loc) { window.location.href = loc; return; }
      }
      const body = await res.json().catch(() => ({})) as { error?: string; redirect_uri?: string };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("Too many failed attempts. Please return to the application and try again.");
      } else {
        setError("Incorrect code — please try again");
      }
    } catch { setError("Network error — please try again"); }
    finally { setLoading(false); }
  };

  if (step === "loading") {
    return <div style={{ textAlign: "center", padding: "24px 0" }}>
      <p className="font-display" style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.08em" }}>
        SETTING UP MFA...
      </p>
      {error && <p style={{ color: "#ef4444", fontSize: "12px" }}>{error}</p>}
    </div>;
  }

  if (step === "setup") {
    return (
      <div>
        <div className="font-display" style={{ fontSize: "10px", letterSpacing: "0.12em",
          textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "16px" }}>
          SET UP AUTHENTICATOR
        </div>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "16px" }}>
          Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
        </p>
        {qrDataUrl && <img src={qrDataUrl} alt="TOTP QR code"
          style={{ display: "block", margin: "0 auto 16px", width: "180px", height: "180px" }} />}
        <div style={{ background: "var(--bg-elevated)", padding: "8px 12px", marginBottom: "24px",
          fontFamily: "'Space Mono', monospace", fontSize: "11px", color: "var(--text-dim)",
          wordBreak: "break-all" }}>
          {secret}
        </div>
        <button type="button" onClick={() => setStep("confirm")} style={primaryButtonStyle(false)}>
          I've Scanned the Code
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleConfirm}>
      <div className="font-display" style={{ fontSize: "10px", letterSpacing: "0.12em",
        textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "16px" }}>
        CONFIRM SETUP
      </div>
      {error && (
        <div style={{ marginBottom: "16px", padding: "10px 12px",
          border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.05)" }}>
          <span className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em" }}>✕ {error}</span>
        </div>
      )}
      <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "16px" }}>
        Enter the 6-digit code from your authenticator app to confirm setup.
      </p>
      <div style={{ marginBottom: "24px" }}>
        <label className="font-display" style={labelStyle}>Confirmation Code</label>
        <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
          value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
          required autoComplete="one-time-code" placeholder="000000"
          style={inputStyle}
          onFocus={e => (e.target.style.borderColor = "var(--accent-cyan)")}
          onBlur={e => (e.target.style.borderColor = "var(--border)")} />
      </div>
      <button type="submit" disabled={loading || code.length !== 6}
        style={primaryButtonStyle(loading || code.length !== 6)}>
        {loading ? "Confirming..." : "Confirm and Sign In"}
      </button>
      <div style={{ textAlign: "center", marginTop: "16px" }}>
        <button type="button" onClick={() => setStep("setup")}
          style={{ background: "none", border: "none", color: "var(--text-muted)",
            fontSize: "12px", cursor: "pointer", textDecoration: "underline" }}>
          Back to QR code
        </button>
      </div>
    </form>
  );
}

// ─── Magic link consume handler ───────────────────────────────────────────────

function MagicLinkConsuming({
  tenantSlug,
  token
}: {
  tenantSlug: string;
  token: string;
}) {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    consumeMagicLink(tenantSlug, token).then(res => {
      if (res.status === 302 || res.type === "opaqueredirect") {
        const location = res.headers.get("location");
        if (location) {
          window.location.href = location;
          return;
        }
      }
      setError("This link has expired or has already been used.");
    }).catch(() => {
      setError("Failed to verify magic link — please request a new one.");
    });
  }, [tenantSlug, token]);

  if (error) {
    return (
      <div style={{ textAlign: "center", padding: "24px 0" }}>
        <p className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em", marginBottom: "8px" }}>
          LINK INVALID
        </p>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{error}</p>
      </div>
    );
  }

  return (
    <div style={{ textAlign: "center", padding: "24px 0" }}>
      <p className="font-display" style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.08em" }}>
        VERIFYING LINK...
      </p>
    </div>
  );
}

// ─── Page shell ───────────────────────────────────────────────────────────────

export default function TenantLoginPage() {
  const { tenant: tenantSlug } = useParams<{ tenant: string }>();
  const [searchParams] = useSearchParams();
  const loginChallenge = searchParams.get("login_challenge") ?? "";
  const magicLinkToken = searchParams.get("token");

  const [info, setInfo] = useState<ChallengeInfo | null>(null);
  const [activeMethod, setActiveMethod] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mfaContext, setMfaContext] = useState<{
    mfaState: MfaState;
    loginChallenge: string;
    hasTotpFallback: boolean;
  } | null>(null);

  useEffect(() => {
    if (!tenantSlug || !loginChallenge) {
      setLoadError("No active login session. Please return to the application and try again.");
      return;
    }
    getChallengeInfo(tenantSlug, loginChallenge).then(data => {
      setInfo(data);
      if (data.methods.length > 0) setActiveMethod(data.methods[0].method);
    }).catch(() => {
      setLoadError("This login session has expired or is invalid. Please return to the application and try again.");
    });
  }, [tenantSlug, loginChallenge]);

  return (
    <div style={{
      minHeight: "100vh",
      background: "var(--bg-base)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      position: "relative",
      overflow: "hidden"
    }} className="dot-grid">
      {/* Corner decoration */}
      <div style={{ position: "absolute", top: "40px", left: "40px", width: "80px", height: "80px", borderTop: "1px solid var(--border-bright)", borderLeft: "1px solid var(--border-bright)" }} />
      <div style={{ position: "absolute", bottom: "40px", right: "40px", width: "80px", height: "80px", borderBottom: "1px solid var(--border-bright)", borderRight: "1px solid var(--border-bright)" }} />

      <div style={{ width: "100%", maxWidth: "400px", padding: "0 24px" }}>
        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: "32px" }}>
          <div style={{
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            width: "48px", height: "48px",
            border: "1px solid var(--accent-cyan)",
            marginBottom: "16px", position: "relative"
          }}>
            <div style={{
              width: "16px", height: "16px",
              background: "var(--accent-cyan)",
              transform: "rotate(45deg)",
              boxShadow: "0 0 12px var(--accent-cyan)"
            }} />
          </div>
          <div className="font-display" style={{ fontSize: "16px", letterSpacing: "0.05em", color: "var(--text-primary)", marginBottom: "4px" }}>
            {info?.tenant_display_name ?? tenantSlug ?? "Sign In"}
          </div>
          <div className="font-display" style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: "var(--text-muted)" }}>
            SECURE SIGN-IN
          </div>
        </div>

        {/* Card */}
        <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)" }}>
          <div style={{ height: "2px", background: "linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))" }} />

          {loadError ? (
            <div style={{ padding: "32px 24px", textAlign: "center" }}>
              <p className="font-display" style={{ fontSize: "10px", color: "#ef4444", letterSpacing: "0.08em", marginBottom: "8px" }}>SESSION ERROR</p>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{loadError}</p>
            </div>
          ) : !info ? (
            <div style={{ padding: "32px 24px", textAlign: "center" }}>
              <p className="font-display" style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.08em" }}>LOADING...</p>
            </div>
          ) : magicLinkToken ? (
            <div style={{ padding: "24px" }}>
              <MagicLinkConsuming tenantSlug={tenantSlug!} token={magicLinkToken} />
            </div>
          ) : mfaContext !== null ? (
            <div style={{ padding: "24px" }}>
              {mfaContext.mfaState === "pending_totp" && (
                <MfaTotpVerifyView
                  tenantSlug={tenantSlug!}
                  loginChallenge={mfaContext.loginChallenge}
                />
              )}
              {mfaContext.mfaState === "pending_passkey_step_up" && (
                <MfaPasskeyStepUpView
                  tenantSlug={tenantSlug!}
                  loginChallenge={mfaContext.loginChallenge}
                  hasTotpFallback={mfaContext.hasTotpFallback}
                  onSwitchToTotp={async () => {
                    await mfaSwitchToTotp(tenantSlug!, mfaContext.loginChallenge);
                    setMfaContext(prev => prev ? { ...prev, mfaState: "pending_totp" } : null);
                  }}
                />
              )}
              {mfaContext.mfaState === "pending_enrollment" && (
                <MfaEnrollTotpView
                  tenantSlug={tenantSlug!}
                  loginChallenge={mfaContext.loginChallenge}
                />
              )}
            </div>
          ) : (
            <>
              {/* Method tabs — only shown when multiple methods available */}
              {info.methods.length > 1 && (
                <div style={{ display: "flex", borderBottom: "1px solid var(--border)" }}>
                  {info.methods.map(({ method }) => (
                    <button
                      key={method}
                      type="button"
                      onClick={() => setActiveMethod(method)}
                      style={tabButtonStyle(activeMethod === method)}
                    >
                      {METHOD_LABELS[method] ?? method}
                    </button>
                  ))}
                </div>
              )}

              <div style={{ padding: "24px" }}>
                {info.methods.length === 0 ? (
                  <p style={{ fontSize: "13px", color: "var(--text-secondary)", textAlign: "center" }}>
                    No login methods are currently available. Please contact your administrator.
                  </p>
                ) : activeMethod === "password" ? (
                  <PasswordForm
                    tenantSlug={tenantSlug!}
                    loginChallenge={loginChallenge}
                    allowRegistration={
                      info.methods.find((m) => m.method === "password")?.allow_registration ?? false
                    }
                    onMfaRequired={(ctx) => setMfaContext(ctx)}
                  />
                ) : activeMethod === "magic_link" ? (
                  <MagicLinkForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
                ) : activeMethod === "passkey" ? (
                  <PasskeyForm
                    tenantSlug={tenantSlug!}
                    loginChallenge={loginChallenge}
                    onMfaRequired={(ctx) => setMfaContext(ctx)}
                  />
                ) : null}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
