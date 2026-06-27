import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "../App";
import { BrandMark } from "./auth/icons";

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
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Logo mark */}
          <div style={{
            width: '30px', height: '30px',
            borderRadius: '9px',
            background: '#fff',
            border: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 1px 4px rgba(34,30,23,.08)'
          }}>
            <BrandMark size={18} />
          </div>
          <Link to="/tenants" className="font-serif" style={{
            color: 'var(--text-primary)',
            textDecoration: 'none',
            fontSize: '16px',
            fontWeight: 600,
            letterSpacing: '0.2px'
          }}>
            ma_hono
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
