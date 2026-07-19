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
import {
  AuthShell,
  BrandPanel,
  FieldLabel,
  fieldWrapStyle,
  iconSpanStyle,
  inputStyle,
  primaryButtonStyle
} from "../components/auth/AuthShell";
import {
  LockIcon,
  MailIcon,
  PasskeyButtonIcon,
  PasskeyIcon,
  UserIcon
} from "../components/auth/icons";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

type MfaState = "pending_totp" | "pending_passkey_step_up" | "pending_enrollment";

// ─── Shared visual behaviour ──────────────────────────────────────────────────

function focusInput(e: React.FocusEvent<HTMLInputElement>) {
  e.target.style.borderColor = "var(--accent-green)";
  e.target.style.boxShadow = "0 0 0 3px rgba(47,122,76,0.14)";
  e.target.style.background = "#fff";
}
function blurInput(e: React.FocusEvent<HTMLInputElement>) {
  e.target.style.borderColor = "var(--border)";
  e.target.style.boxShadow = "none";
  e.target.style.background = "var(--bg-input)";
}
function hoverPrimary(e: React.MouseEvent<HTMLButtonElement>) {
  if (!e.currentTarget.disabled) e.currentTarget.style.background = "var(--accent-green-deep)";
}
function unhoverPrimary(e: React.MouseEvent<HTMLButtonElement>) {
  if (!e.currentTarget.disabled) e.currentTarget.style.background = "var(--accent-green)";
}

const pwToggleStyle: React.CSSProperties = {
  position: "absolute", right: "8px", top: "50%", transform: "translateY(-50%)",
  border: 0, background: "transparent", color: "var(--text-secondary)",
  fontSize: "12px", fontWeight: 600, cursor: "pointer", padding: "6px 8px", borderRadius: "7px"
};

const linkStyle: React.CSSProperties = {
  fontSize: "12px", fontWeight: 600, color: "var(--accent-green)", textDecoration: "none",
  background: "none", border: "none", cursor: "pointer", padding: 0
};

function ErrorBanner({ message }: { message: string }) {
  return (
    <div style={{
      marginBottom: "18px", padding: "10px 12px", borderRadius: "10px",
      border: "1px solid rgba(204,107,58,0.35)", background: "rgba(204,107,58,0.07)"
    }}>
      <span style={{ fontSize: "12.5px", color: "var(--accent-orange)", fontWeight: 600 }}>✕ {message}</span>
    </div>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--accent-orange)", marginBottom: "16px" }}>
      {children}
    </div>
  );
}

// ─── Method tabs ───────────────────────────────────────────────────────────────

const METHOD_LABELS: Record<string, string> = {
  password: "密码",
  magic_link: "邮箱链接",
  passkey: "通行密钥"
};

function MethodTabs({
  methods,
  active,
  onSelect
}: {
  methods: string[];
  active: string | null;
  onSelect: (m: string) => void;
}) {
  return (
    <div style={{ display: "flex", gap: "4px", padding: "4px", background: "#ece7db", borderRadius: "11px", marginBottom: "26px" }}>
      {methods.map(method => {
        const isActive = active === method;
        return (
          <button
            key={method}
            type="button"
            onClick={() => onSelect(method)}
            style={{
              flex: 1, textAlign: "center", padding: "9px 8px", border: 0, borderRadius: "8px",
              fontFamily: "inherit", fontSize: "13px", fontWeight: 600, cursor: "pointer",
              transition: "all .15s",
              background: isActive ? "#ffffff" : "transparent",
              color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
              boxShadow: isActive ? "0 1px 3px rgba(34,30,23,.14)" : "none"
            }}
          >
            {METHOD_LABELS[method] ?? method}
          </button>
        );
      })}
    </div>
  );
}

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
      setError("两次输入的密码不一致");
      return;
    }
    if (password.length < 8) {
      setError("密码至少需要 8 个字符");
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
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        if (body.error === "email_already_exists") {
          setError("该邮箱已注册，请直接登录。");
        } else {
          setError(body.error ?? "注册失败");
        }
        return;
      }
      const body = await res.json().catch(() => ({})) as { redirect_uri?: string };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
    } catch {
      setError("网络错误 — 请重试");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <ErrorBanner message={error} />}
      <FieldLabel>邮箱地址</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "16px" }}>
        <span style={iconSpanStyle}><MailIcon /></span>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email"
          placeholder="alice@example.com" style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <FieldLabel>用户名（可选）</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "16px" }}>
        <span style={iconSpanStyle}><UserIcon /></span>
        <input type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username"
          style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <FieldLabel>密码</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "16px" }}>
        <span style={iconSpanStyle}><LockIcon /></span>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="new-password"
          placeholder="••••••••••" style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <FieldLabel>确认密码</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "24px" }}>
        <span style={iconSpanStyle}><LockIcon /></span>
        <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required autoComplete="new-password"
          placeholder="••••••••••" style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)} onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
        {loading ? "创建中…" : "创建账号"}
      </button>
      <div style={{ textAlign: "center", marginTop: "16px" }}>
        <button type="button" onClick={onBackToSignIn} style={{ ...linkStyle, color: "var(--text-muted)" }}>
          返回登录
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
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await loginWithPassword(tenantSlug, loginChallenge, username, password);
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? "登录失败");
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
      setError("网络错误 — 请重试");
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
      {error && <ErrorBanner message={error} />}
      <FieldLabel>用户名或邮箱</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "18px" }}>
        <span style={iconSpanStyle}><UserIcon /></span>
        <input
          type="text" value={username} onChange={e => setUsername(e.target.value)} required autoComplete="username"
          placeholder="alice@example.com" style={inputStyle} onFocus={focusInput} onBlur={blurInput}
        />
      </div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "7px" }}>
        <label style={{ fontSize: "12px", fontWeight: 600, color: "var(--text-secondary)" }}>密码</label>
        <a href="#" style={linkStyle as React.CSSProperties}>忘记密码？</a>
      </div>
      <div style={{ ...fieldWrapStyle, marginBottom: "24px" }}>
        <span style={iconSpanStyle}><LockIcon /></span>
        <input
          type={showPw ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)} required autoComplete="current-password"
          placeholder="••••••••••" style={{ ...inputStyle, paddingRight: "64px" }} onFocus={focusInput} onBlur={blurInput}
        />
        <button type="button" onClick={() => setShowPw(s => !s)} style={pwToggleStyle}>{showPw ? "隐藏" : "显示"}</button>
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)} onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
        {loading ? "登录中…" : "登录"}
      </button>
      {allowRegistration && (
        <div style={{ textAlign: "center", marginTop: "16px", fontSize: "12.5px", color: "var(--text-muted)" }}>
          还没有账号？{" "}
          <button type="button" onClick={() => setShowRegister(true)} style={linkStyle}>注册</button>
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
      setError("发送登录链接失败 — 请重试");
    } finally {
      setLoading(false);
    }
  };

  if (sent) {
    return (
      <div style={{ textAlign: "center", padding: "16px 0" }}>
        <div style={{ display: "grid", placeItems: "center", width: "64px", height: "64px", borderRadius: "18px", background: "#e7f0e4", margin: "0 auto 18px" }}>
          <MailIcon size={28} color="var(--accent-green)" />
        </div>
        <h3 className="font-serif" style={{ margin: "0 0 8px", fontWeight: 600, fontSize: "19px", color: "var(--text-primary)" }}>请查收邮箱</h3>
        <p style={{ fontSize: "13px", lineHeight: 1.6, color: "var(--text-secondary)" }}>
          登录链接已发送至 <strong style={{ color: "var(--text-primary)" }}>{email}</strong>，点击邮件中的链接即可完成登录。
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      {error && <ErrorBanner message={error} />}
      <FieldLabel>邮箱地址</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "18px" }}>
        <span style={iconSpanStyle}><MailIcon /></span>
        <input
          type="email" value={email} onChange={e => setEmail(e.target.value)} required autoComplete="email"
          placeholder="alice@example.com" style={inputStyle} onFocus={focusInput} onBlur={blurInput}
        />
      </div>
      <div style={{ display: "flex", gap: "9px", alignItems: "flex-start", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "11px", padding: "13px 14px", marginBottom: "24px" }}>
        <span style={{ flexShrink: 0, marginTop: "1px" }}><MailIcon size={17} color="var(--accent-orange)" /></span>
        <span style={{ fontSize: "12.5px", lineHeight: 1.55, color: "var(--text-secondary)" }}>
          我们会向你的邮箱发送一个一次性登录链接，点击即可完成登录，无需密码。
        </span>
      </div>
      <button type="submit" disabled={loading} style={primaryButtonStyle(loading)} onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
        {loading ? "发送中…" : "发送登录链接"}
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
        setError("未选择通行密钥");
        return;
      }

      const res = await finishPasskeyLogin(tenantSlug, startResult.assertion_session_id, credential);
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? "通行密钥验证失败");
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
        setError("通行密钥操作已取消");
      } else {
        setError("通行密钥验证失败 — 请重试");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", paddingTop: "6px" }}>
      {error && <div style={{ alignSelf: "stretch" }}><ErrorBanner message={error} /></div>}
      <div style={{ display: "grid", placeItems: "center", width: "64px", height: "64px", borderRadius: "18px", background: "#e7f0e4", marginBottom: "18px" }}>
        <PasskeyIcon size={30} />
      </div>
      <h3 className="font-serif" style={{ margin: "0 0 8px", fontWeight: 600, fontSize: "19px", color: "var(--text-primary)" }}>使用通行密钥登录</h3>
      <p style={{ margin: "0 0 24px", fontSize: "13px", lineHeight: 1.6, color: "var(--text-secondary)", maxWidth: "300px" }}>
        通过设备的指纹、面容或屏幕锁验证你的身份，安全且免密。
      </p>
      <button
        type="button" disabled={loading} onClick={handlePasskeyLogin}
        style={{ ...primaryButtonStyle(loading), display: "flex", alignItems: "center", justifyContent: "center", gap: "9px" }}
        onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}
      >
        <PasskeyButtonIcon />
        {loading ? "等待通行密钥…" : "验证通行密钥"}
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
      const body = await res.json().catch(() => ({})) as {
        error?: string; remaining_attempts?: number; redirect_uri?: string
      };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("失败次数过多，请返回应用后重试。");
      } else {
        setError(`验证码错误${body.remaining_attempts !== undefined ? ` — 还剩 ${body.remaining_attempts} 次机会` : ""}`);
      }
    } catch { setError("网络错误 — 请重试"); }
    finally { setLoading(false); }
  };

  return (
    <form onSubmit={handleVerify}>
      <Eyebrow>两步验证</Eyebrow>
      {error && <ErrorBanner message={error} />}
      <FieldLabel>验证器代码</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "24px" }}>
        <span style={iconSpanStyle}><LockIcon /></span>
        <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
          value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
          required autoComplete="one-time-code" placeholder="000000"
          style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <button type="submit" disabled={loading || code.length !== 6} style={primaryButtonStyle(loading || code.length !== 6)}
        onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
        {loading ? "验证中…" : "验证"}
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
      if (!credential) { setError("未选择通行密钥"); return; }
      // Pass the raw nonce; mfaPasskeyFinish will SHA-256 hash it before sending to the server
      const res = await mfaPasskeyFinish(tenantSlug, loginChallenge, startResult.challenge, credential);
      const body = await res.json().catch(() => ({})) as { error?: string; redirect_uri?: string };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("失败次数过多，请返回应用后重试。");
      } else {
        setError("通行密钥验证失败 — 请重试");
      }
    } catch (err) {
      if (err instanceof Error && err.name === "NotAllowedError") setError("通行密钥操作已取消");
      else setError("通行密钥验证失败 — 请重试");
    } finally { setLoading(false); }
  };

  return (
    <div>
      <Eyebrow>通行密钥验证</Eyebrow>
      {error && <ErrorBanner message={error} />}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
        <div style={{ display: "grid", placeItems: "center", width: "64px", height: "64px", borderRadius: "18px", background: "#e7f0e4", marginBottom: "18px" }}>
          <PasskeyIcon size={30} />
        </div>
        <p style={{ margin: "0 0 24px", fontSize: "13px", lineHeight: 1.6, color: "var(--text-secondary)", maxWidth: "300px" }}>
          使用你已注册的通行密钥完成登录。
        </p>
        <button type="button" disabled={loading} onClick={handleStepUp}
          style={{ ...primaryButtonStyle(loading), display: "flex", alignItems: "center", justifyContent: "center", gap: "9px" }}
          onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
          <PasskeyButtonIcon />
          {loading ? "等待通行密钥…" : "使用通行密钥验证"}
        </button>
        {hasTotpFallback && (
          <button type="button" onClick={onSwitchToTotp} style={{ ...linkStyle, color: "var(--text-muted)", marginTop: "16px" }}>
            改用验证器应用
          </button>
        )}
      </div>
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
      .catch(() => setError("启动绑定失败 — 请重试"));
  }, [tenantSlug, loginChallenge]);

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setLoading(true);
    try {
      const res = await mfaEnrollFinish(tenantSlug, loginChallenge, code);
      const body = await res.json().catch(() => ({})) as { error?: string; redirect_uri?: string };
      if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      if (body.error === "challenge_invalidated") {
        setError("失败次数过多，请返回应用后重试。");
      } else {
        setError("验证码错误 — 请重试");
      }
    } catch { setError("网络错误 — 请重试"); }
    finally { setLoading(false); }
  };

  if (step === "loading") {
    return <div style={{ textAlign: "center", padding: "24px 0" }}>
      <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>正在设置两步验证…</p>
      {error && <p style={{ color: "var(--accent-orange)", fontSize: "12.5px" }}>{error}</p>}
    </div>;
  }

  if (step === "setup") {
    return (
      <div>
        <Eyebrow>设置验证器</Eyebrow>
        <p style={{ fontSize: "13px", lineHeight: 1.6, color: "var(--text-secondary)", marginBottom: "16px" }}>
          使用验证器应用（Google Authenticator、Authy 等）扫描下方二维码。
        </p>
        {qrDataUrl && <img src={qrDataUrl} alt="TOTP 二维码"
          style={{ display: "block", margin: "0 auto 16px", width: "180px", height: "180px", borderRadius: "12px", border: "1px solid var(--border)" }} />}
        <div style={{ background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "10px", padding: "10px 12px", marginBottom: "24px",
          fontFamily: "monospace", fontSize: "12px", color: "var(--text-secondary)", wordBreak: "break-all" }}>
          {secret}
        </div>
        <button type="button" onClick={() => setStep("confirm")} style={primaryButtonStyle(false)}
          onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
          我已扫描二维码
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleConfirm}>
      <Eyebrow>确认设置</Eyebrow>
      {error && <ErrorBanner message={error} />}
      <p style={{ fontSize: "13px", lineHeight: 1.6, color: "var(--text-secondary)", marginBottom: "16px" }}>
        输入验证器应用中的 6 位验证码以确认设置。
      </p>
      <FieldLabel>确认验证码</FieldLabel>
      <div style={{ ...fieldWrapStyle, marginBottom: "24px" }}>
        <span style={iconSpanStyle}><LockIcon /></span>
        <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
          value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
          required autoComplete="one-time-code" placeholder="000000"
          style={inputStyle} onFocus={focusInput} onBlur={blurInput} />
      </div>
      <button type="submit" disabled={loading || code.length !== 6} style={primaryButtonStyle(loading || code.length !== 6)}
        onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
        {loading ? "确认中…" : "确认并登录"}
      </button>
      <div style={{ textAlign: "center", marginTop: "16px" }}>
        <button type="button" onClick={() => setStep("setup")} style={{ ...linkStyle, color: "var(--text-muted)" }}>
          返回二维码
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
    consumeMagicLink(tenantSlug, token).then(async res => {
      if (res.ok) {
        const body = await res.json().catch(() => ({})) as { redirect_uri?: string };
        if (body.redirect_uri) { window.location.href = body.redirect_uri; return; }
      }
      setError("此链接已失效或已被使用。");
    }).catch(() => {
      setError("验证登录链接失败 — 请重新申请。");
    });
  }, [tenantSlug, token]);

  if (error) {
    return (
      <div style={{ textAlign: "center", padding: "24px 0" }}>
        <h3 className="font-serif" style={{ margin: "0 0 8px", fontWeight: 600, fontSize: "18px", color: "var(--accent-orange)" }}>链接无效</h3>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{error}</p>
      </div>
    );
  }

  return (
    <div style={{ textAlign: "center", padding: "24px 0" }}>
      <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>正在验证链接…</p>
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
    let ignore = false;

    setInfo(null);
    setActiveMethod(null);
    setLoadError(null);

    if (!tenantSlug || !loginChallenge) {
      setLoadError("没有有效的登录会话，请返回应用后重试。");
      return;
    }
    getChallengeInfo(tenantSlug, loginChallenge).then(data => {
      if (ignore) return;
      setInfo(data);
      if (data.methods.length > 0) setActiveMethod(data.methods[0].method);
    }).catch(() => {
      if (ignore) return;
      setLoadError("此登录会话已过期或无效，请返回应用后重试。");
    });

    return () => {
      ignore = true;
    };
  }, [tenantSlug, loginChallenge]);

  const tenantName = info?.tenant_display_name ?? "Workspace";
  const tenantInitial = tenantName.trim().charAt(0) || "·";

  useDocumentTitle(info ? `登录到 ${info.tenant_display_name}` : undefined);

  return (
    <AuthShell>
      <BrandPanel
        heading={<>一次登录<br />畅行工作区</>}
        description="密码、邮箱链接或通行密钥，选择你习惯的方式安全登入。"
        footer={
          <div style={{ display: "flex", alignItems: "center", gap: "9px", background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: "12px", padding: "10px 12px" }}>
            <span className="font-serif" style={{ display: "grid", placeItems: "center", width: "30px", height: "30px", flexShrink: 0, borderRadius: "8px", background: "var(--accent-green)", color: "#fff", fontWeight: 600, fontSize: "15px" }}>
              {tenantInitial}
            </span>
            <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.3, minWidth: 0 }}>
              <span style={{ fontSize: "9px", letterSpacing: "0.16em", textTransform: "uppercase", color: "var(--text-muted)" }}>继续登录到</span>
              <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{tenantName}</span>
            </span>
          </div>
        }
      />

      {/* Form panel */}
      <div style={{ flex: 1, padding: "44px 44px", display: "flex", flexDirection: "column", background: "#ffffff", minWidth: 0 }}>
        {loadError ? (
          <div style={{ margin: "auto 0", textAlign: "center" }}>
            <h1 className="font-serif" style={{ margin: "0 0 10px", fontWeight: 600, fontSize: "22px", color: "var(--accent-orange)" }}>会话错误</h1>
            <p style={{ fontSize: "13.5px", lineHeight: 1.6, color: "var(--text-secondary)" }}>{loadError}</p>
          </div>
        ) : !info ? (
          <div style={{ margin: "auto 0", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>加载中…</div>
        ) : magicLinkToken ? (
          <div style={{ margin: "auto 0" }}>
            <MagicLinkConsuming tenantSlug={tenantSlug!} token={magicLinkToken} />
          </div>
        ) : mfaContext !== null ? (
          <div>
            <div style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--accent-orange)", marginBottom: "10px" }}>Verify</div>
            <h1 className="font-serif" style={{ margin: "0 0 24px", fontWeight: 600, fontSize: "26px", color: "var(--text-primary)" }}>安全验证</h1>
            {mfaContext.mfaState === "pending_totp" && (
              <MfaTotpVerifyView tenantSlug={tenantSlug!} loginChallenge={mfaContext.loginChallenge} />
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
              <MfaEnrollTotpView tenantSlug={tenantSlug!} loginChallenge={mfaContext.loginChallenge} />
            )}
          </div>
        ) : (
          <>
            <div style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--accent-orange)", marginBottom: "10px" }}>Sign in</div>
            <h1 className="font-serif" style={{ margin: "0 0 8px", fontWeight: 600, fontSize: "30px", color: "var(--text-primary)", letterSpacing: "0.2px" }}>欢迎回来</h1>
            <p style={{ margin: "0 0 24px", fontSize: "13.5px", lineHeight: 1.6, color: "var(--text-secondary)" }}>选择一种方式登录以继续。</p>

            {info.methods.length > 1 && (
              <MethodTabs
                methods={info.methods.map(m => m.method)}
                active={activeMethod}
                onSelect={setActiveMethod}
              />
            )}

            {info.methods.length === 0 ? (
              <p style={{ fontSize: "13px", color: "var(--text-secondary)", textAlign: "center" }}>
                当前没有可用的登录方式，请联系管理员。
              </p>
            ) : activeMethod === "password" ? (
              <PasswordForm
                tenantSlug={tenantSlug!}
                loginChallenge={loginChallenge}
                allowRegistration={info.methods.find((m) => m.method === "password")?.allow_registration ?? false}
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

            <div style={{ marginTop: "auto", paddingTop: "26px", textAlign: "center", fontSize: "12.5px", color: "var(--text-muted)" }}>
              还没有账号？<a href="#" style={{ color: "var(--accent-green)", fontWeight: 600, textDecoration: "none" }}>联系管理员邀请</a>
            </div>
          </>
        )}
      </div>
    </AuthShell>
  );
}
