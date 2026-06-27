import { useState } from "react";
import { useNavigate } from "react-router";
import { login } from "../api/client";
import { useAuth } from "../App";
import { AuthShell, BrandPanel, FieldLabel, fieldWrapStyle, iconSpanStyle, inputStyle, primaryButtonStyle } from "../components/auth/AuthShell";
import { LockIcon, MailIcon } from "../components/auth/icons";

export default function LoginPage() {
  const { setToken } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await login(email, password);
      setToken(res.session_token);
      navigate("/tenants");
    } catch {
      setError("登录失败 — 请检查邮箱与密码");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell>
      <BrandPanel
        heading={<>统一身份<br />认证平台</>}
        description="面向多租户的 OIDC 身份提供方，为每个工作区颁发可信凭证。"
        footer={
          <div style={{ display: "flex", flexWrap: "wrap", gap: "7px" }}>
            {["OIDC", "PKCE", "RS256"].map(tag => (
              <span key={tag} style={{
                fontSize: "10.5px", fontWeight: 600, letterSpacing: "0.06em",
                color: "var(--accent-green)", background: "var(--bg-surface)",
                border: "1px solid var(--border)", borderRadius: "999px", padding: "5px 11px"
              }}>{tag}</span>
            ))}
          </div>
        }
      />

      {/* Form panel */}
      <div style={{ flex: 1, padding: "46px 44px", display: "flex", flexDirection: "column", background: "#ffffff" }}>
        <div style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--accent-orange)", marginBottom: "10px" }}>
          Admin Console
        </div>
        <h1 className="font-serif" style={{ margin: "0 0 8px", fontWeight: 600, fontSize: "30px", color: "var(--text-primary)", letterSpacing: "0.2px" }}>
          管理员登录
        </h1>
        <p style={{ margin: "0 0 30px", fontSize: "13.5px", lineHeight: 1.6, color: "var(--text-secondary)" }}>
          登录以管理租户、用户与 OIDC 客户端。
        </p>

        <form onSubmit={handleSubmit}>
          {error && (
            <div style={{
              marginBottom: "18px", padding: "10px 12px", borderRadius: "10px",
              border: "1px solid rgba(204,107,58,0.35)", background: "rgba(204,107,58,0.07)"
            }}>
              <span style={{ fontSize: "12.5px", color: "var(--accent-orange)", fontWeight: 600 }}>✕ {error}</span>
            </div>
          )}

          <FieldLabel>邮箱地址</FieldLabel>
          <div style={{ ...fieldWrapStyle, marginBottom: "18px" }}>
            <span style={iconSpanStyle}><MailIcon /></span>
            <input
              type="email" value={email} onChange={e => setEmail(e.target.value)}
              required autoComplete="email" placeholder="admin@example.com"
              style={inputStyle}
              onFocus={focusInput} onBlur={blurInput}
            />
          </div>

          <FieldLabel>密码</FieldLabel>
          <div style={{ ...fieldWrapStyle, marginBottom: "14px" }}>
            <span style={iconSpanStyle}><LockIcon /></span>
            <input
              type={showPw ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)}
              required autoComplete="current-password" placeholder="••••••••••"
              style={{ ...inputStyle, paddingRight: "64px" }}
              onFocus={focusInput} onBlur={blurInput}
            />
            <button type="button" onClick={() => setShowPw(s => !s)} style={pwToggleStyle}>
              {showPw ? "隐藏" : "显示"}
            </button>
          </div>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "26px" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12.5px", color: "var(--text-secondary)", cursor: "pointer" }}>
              <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)}
                style={{ width: "15px", height: "15px", accentColor: "var(--accent-green)", cursor: "pointer" }} />
              保持登录
            </label>
          </div>

          <button type="submit" disabled={loading} style={primaryButtonStyle(loading)}
            onMouseEnter={hoverPrimary} onMouseLeave={unhoverPrimary}>
            {loading ? "登录中…" : "登录控制台"}
          </button>
        </form>

        <div style={{ marginTop: "auto", paddingTop: "30px", display: "flex", alignItems: "center", gap: "7px", color: "var(--text-muted)", fontSize: "11.5px" }}>
          <LockIcon size={13} />
          受 ma_hono 加密保护 · 仅限授权管理员
        </div>
      </div>
    </AuthShell>
  );
}

// ─── focus/hover handlers (shared visual behaviour) ───────────────────────────

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
