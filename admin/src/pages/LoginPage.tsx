import { useState } from "react";
import { useNavigate } from "react-router";
import { login } from "../api/client";
import { useAuth } from "../App";

export default function LoginPage() {
  const { setToken } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
      setError("AUTH FAILED — CHECK CREDENTIALS");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-base)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden'
    }}
    className="dot-grid"
    >
      {/* Decorative corner lines */}
      <div style={{
        position: 'absolute', top: '40px', left: '40px',
        width: '80px', height: '80px',
        borderTop: '1px solid var(--border-bright)',
        borderLeft: '1px solid var(--border-bright)'
      }} />
      <div style={{
        position: 'absolute', bottom: '40px', right: '40px',
        width: '80px', height: '80px',
        borderBottom: '1px solid var(--border-bright)',
        borderRight: '1px solid var(--border-bright)'
      }} />

      {/* Glow */}
      <div style={{
        position: 'absolute',
        width: '400px', height: '400px',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0,229,255,0.04) 0%, transparent 70%)',
        pointerEvents: 'none'
      }} />

      <div style={{ width: '100%', maxWidth: '380px', padding: '0 24px' }}>
        {/* Logo area */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '48px', height: '48px',
            border: '1px solid var(--accent-cyan)',
            marginBottom: '16px',
            position: 'relative'
          }}>
            <div style={{
              width: '16px', height: '16px',
              background: 'var(--accent-cyan)',
              transform: 'rotate(45deg)',
              boxShadow: '0 0 12px var(--accent-cyan)'
            }} />
          </div>
          <div className="font-display" style={{
            fontSize: '13px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)'
          }}>
            ADMIN ACCESS
          </div>
        </div>

        {/* Form panel */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          position: 'relative'
        }}>
          <div style={{
            height: '2px',
            background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))'
          }} />

          {error && (
            <div style={{
              padding: '10px 20px',
              borderBottom: '1px solid rgba(239,68,68,0.3)',
              background: 'rgba(239,68,68,0.05)'
            }}>
              <span className="font-display" style={{
                fontSize: '10px',
                color: '#ef4444',
                letterSpacing: '0.08em'
              }}>
                ✕ {error}
              </span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
            <div style={{ marginBottom: '16px' }}>
              <label className="font-display" style={{
                display: 'block',
                fontSize: '10px',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                color: 'var(--text-muted)',
                marginBottom: '6px'
              }}>
                EMAIL
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoComplete="email"
                style={{
                  width: '100%',
                  background: 'var(--bg-base)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-primary)',
                  padding: '8px 12px',
                  fontSize: '13px',
                  fontFamily: "'IBM Plex Sans', sans-serif",
                  outline: 'none',
                  boxSizing: 'border-box',
                  transition: 'border-color 0.15s'
                }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <div style={{ marginBottom: '24px' }}>
              <label className="font-display" style={{
                display: 'block',
                fontSize: '10px',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
                color: 'var(--text-muted)',
                marginBottom: '6px'
              }}>
                PASSWORD
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                style={{
                  width: '100%',
                  background: 'var(--bg-base)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-primary)',
                  padding: '8px 12px',
                  fontSize: '13px',
                  fontFamily: "'IBM Plex Sans', sans-serif",
                  outline: 'none',
                  boxSizing: 'border-box',
                  transition: 'border-color 0.15s'
                }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                background: loading ? 'var(--bg-elevated)' : 'transparent',
                border: '1px solid var(--accent-cyan)',
                color: loading ? 'var(--text-muted)' : 'var(--accent-cyan)',
                padding: '10px',
                fontSize: '11px',
                fontFamily: "'Space Mono', monospace",
                letterSpacing: '0.15em',
                textTransform: 'uppercase',
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'all 0.15s',
                boxShadow: loading ? 'none' : '0 0 12px rgba(0,229,255,0.1)'
              }}
              onMouseEnter={e => {
                if (!loading) {
                  (e.target as HTMLButtonElement).style.background = 'rgba(0,229,255,0.08)';
                  (e.target as HTMLButtonElement).style.boxShadow = '0 0 20px rgba(0,229,255,0.2)';
                }
              }}
              onMouseLeave={e => {
                if (!loading) {
                  (e.target as HTMLButtonElement).style.background = 'transparent';
                  (e.target as HTMLButtonElement).style.boxShadow = '0 0 12px rgba(0,229,255,0.1)';
                }
              }}
            >
              {loading ? "AUTHENTICATING..." : "AUTHENTICATE"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
