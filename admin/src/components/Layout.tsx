import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "../App";

export default function Layout({ children }: { children: ReactNode }) {
  const { setToken } = useAuth();
  const navigate = useNavigate();

  const signOut = () => {
    setToken(null);
    navigate("/login");
  };

  return (
    <div className="min-h-screen dot-grid" style={{ background: 'var(--bg-base)' }}>
      {/* Top nav */}
      <nav style={{
        background: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border)',
        padding: '0 1.5rem',
        height: '52px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Logo mark */}
          <div style={{
            width: '28px', height: '28px',
            border: '1px solid var(--accent-cyan)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{
              width: '10px', height: '10px',
              background: 'var(--accent-cyan)',
              transform: 'rotate(45deg)'
            }} />
          </div>
          <Link to="/tenants" className="font-display" style={{
            color: 'var(--text-primary)',
            textDecoration: 'none',
            fontSize: '13px',
            letterSpacing: '0.08em',
            textTransform: 'uppercase'
          }}>
            MA / ADMIN
          </Link>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <span className="font-display" style={{
            fontSize: '10px',
            color: 'var(--accent-green)',
            letterSpacing: '0.12em',
            textTransform: 'uppercase'
          }}>
            ● ONLINE
          </span>
          <button
            onClick={signOut}
            className="font-display"
            style={{
              background: 'transparent',
              border: '1px solid var(--border-bright)',
              color: 'var(--text-muted)',
              padding: '4px 12px',
              fontSize: '11px',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              transition: 'all 0.15s'
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--accent-cyan)';
              e.currentTarget.style.color = 'var(--accent-cyan)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--border-bright)';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            SIGN OUT
          </button>
        </div>
      </nav>

      {/* Main */}
      <main style={{ maxWidth: '1100px', margin: '0 auto', padding: '2rem 1.5rem' }}>
        {children}
      </main>
    </div>
  );
}
