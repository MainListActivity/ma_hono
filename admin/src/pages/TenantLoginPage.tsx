import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import {
  type ChallengeInfo,
  consumeMagicLink,
  getChallengeInfo,
  loginWithPassword,
  requestMagicLink
} from "../api/client";

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

function PasswordForm({
  tenantSlug,
  loginChallenge
}: {
  tenantSlug: string;
  loginChallenge: string;
}) {
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
      const body = await res.json().catch(() => ({})) as { redirect_uri?: string };
      if (body.redirect_uri) window.location.href = body.redirect_uri;
    } catch {
      setError("Network error — please try again");
    } finally {
      setLoading(false);
    }
  };

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
  loginChallenge
}: {
  tenantSlug: string;
  loginChallenge: string;
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
      }
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

  useEffect(() => {
    if (!tenantSlug || !loginChallenge) {
      setLoadError("No active login session. Please return to the application and try again.");
      return;
    }
    getChallengeInfo(tenantSlug, loginChallenge).then(data => {
      setInfo(data);
      if (data.methods.length > 0) setActiveMethod(data.methods[0]);
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
          ) : (
            <>
              {/* Method tabs — only shown when multiple methods available */}
              {info.methods.length > 1 && (
                <div style={{ display: "flex", borderBottom: "1px solid var(--border)" }}>
                  {info.methods.map(method => (
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
                  <PasswordForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
                ) : activeMethod === "magic_link" ? (
                  <MagicLinkForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
                ) : activeMethod === "passkey" ? (
                  <PasskeyForm tenantSlug={tenantSlug!} loginChallenge={loginChallenge} />
                ) : null}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
