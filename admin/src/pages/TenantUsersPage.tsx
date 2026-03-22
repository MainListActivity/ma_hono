import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router";
import {
  getTenant,
  listUsers,
  provisionUser,
  type TenantSummary,
  type UserSummary
} from "../api/client";
import { useAuth } from "../App";
import Modal from "../components/Modal";

const inputStyle: React.CSSProperties = {
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
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: '10px',
  letterSpacing: '0.12em',
  textTransform: 'uppercase' as const,
  color: 'var(--text-muted)',
  marginBottom: '6px',
  fontFamily: "'Space Mono', monospace"
};

const statusColor = (status: string) => {
  switch (status) {
    case 'active': return 'var(--accent-green)';
    case 'provisioned': return 'var(--accent-amber)';
    default: return 'var(--text-dim)';
  }
};

export default function TenantUsersPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { token } = useAuth();
  const navigate = useNavigate();
  const [tenant, setTenant] = useState<TenantSummary | null>(null);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const load = async () => {
    if (!token || !tenantId) return;
    setLoading(true);
    setLoadError(null);
    try {
      const [tenantData, usersData] = await Promise.all([
        getTenant(token, tenantId),
        listUsers(token, tenantId)
      ]);
      setTenant(tenantData);
      setUsers(usersData.users);
    } catch {
      setLoadError("FAILED TO LOAD DATA");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [token, tenantId]);

  const handleProvision = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!email.trim() || !displayName.trim()) {
      setFormError("EMAIL AND DISPLAY NAME REQUIRED");
      return;
    }
    setSubmitting(true);
    try {
      await provisionUser(
        token!, tenantId!,
        email.trim(), displayName.trim(),
        username.trim() || undefined
      );
      setShowModal(false);
      setEmail(""); setDisplayName(""); setUsername("");
      await load();
    } catch {
      setFormError("FAILED — EMAIL MAY ALREADY EXIST");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)' }}>
        <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>
          LOADING...
        </span>
      </div>
    );
  }

  if (loadError) {
    return (
      <div style={{
        textAlign: 'center', padding: '60px 0',
        border: '1px solid rgba(239,68,68,0.3)',
        color: '#ef4444'
      }}>
        <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>
          ✕ {loadError}
        </span>
      </div>
    );
  }

  return (
    <div>
      {/* Breadcrumb + header */}
      <div style={{ marginBottom: '28px', paddingBottom: '20px', borderBottom: '1px solid var(--border)' }}>
        <div className="font-display" style={{
          fontSize: '10px',
          letterSpacing: '0.2em',
          textTransform: 'uppercase',
          color: 'var(--text-dim)',
          marginBottom: '6px'
        }}>
          PLATFORM / TENANTS / <span style={{ color: 'var(--accent-cyan)' }}>{tenant?.slug ?? tenantId}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{
              margin: 0,
              fontSize: '22px',
              fontWeight: 300,
              color: 'var(--text-primary)',
              letterSpacing: '0.02em'
            }}>
              {tenant?.display_name ?? tenantId}
            </h1>
            <div style={{
              marginTop: '4px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              fontFamily: "'Space Mono', monospace"
            }}>
              {users.length} USER{users.length !== 1 ? 'S' : ''}
              {tenant?.issuer && (
                <span style={{ marginLeft: '16px', color: 'var(--text-dim)' }}>
                  {tenant.issuer}
                </span>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => navigate(`/tenants/${tenantId}/clients`)}
            style={{
              background: 'transparent',
              border: '1px solid var(--border)',
              color: 'var(--text-muted)',
              padding: '8px 16px',
              fontSize: '11px',
              fontFamily: "'Space Mono', monospace",
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              whiteSpace: 'nowrap'
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent-cyan)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-cyan)'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)'; }}
          >
            CLIENTS →
          </button>
          <button
            onClick={() => { setShowModal(true); setFormError(null); }}
            style={{
              background: 'transparent',
              border: '1px solid var(--accent-cyan)',
              color: 'var(--accent-cyan)',
              padding: '8px 16px',
              fontSize: '11px',
              fontFamily: "'Space Mono', monospace",
              letterSpacing: '0.12em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s',
              whiteSpace: 'nowrap'
            }}
            onMouseEnter={e => {
              const el = e.currentTarget;
              el.style.background = 'rgba(0,229,255,0.08)';
              el.style.boxShadow = '0 0 16px rgba(0,229,255,0.15)';
            }}
            onMouseLeave={e => {
              const el = e.currentTarget;
              el.style.background = 'transparent';
              el.style.boxShadow = 'none';
            }}
          >
            <span style={{ fontSize: '14px', lineHeight: '1' }}>+</span>
            PROVISION USER
          </button>
          </div>
        </div>
      </div>

      {/* Users table */}
      {users.length === 0 ? (
        <div style={{
          textAlign: 'center', padding: '60px 0',
          border: '1px dashed var(--border)',
          color: 'var(--text-muted)'
        }}>
          <div className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em', marginBottom: '8px' }}>
            NO USERS FOUND
          </div>
          <div style={{ fontSize: '13px' }}>Provision the first user for this tenant</div>
        </div>
      ) : (
        <div style={{
          border: '1px solid var(--border)',
          background: 'var(--bg-surface)',
          overflow: 'hidden'
        }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '2fr 1.5fr 100px',
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-elevated)'
          }}>
            {['EMAIL', 'DISPLAY NAME', 'STATUS'].map(h => (
              <span key={h} className="font-display" style={{
                fontSize: '9px',
                letterSpacing: '0.15em',
                color: 'var(--text-dim)',
                textTransform: 'uppercase'
              }}>{h}</span>
            ))}
          </div>

          {users.map((u, i) => (
            <div
              key={u.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '2fr 1.5fr 100px',
                padding: '12px 16px',
                borderBottom: i < users.length - 1 ? '1px solid var(--border)' : 'none',
                alignItems: 'center'
              }}
            >
              <span style={{
                fontFamily: "'Space Mono', monospace",
                fontSize: '12px',
                color: 'var(--text-primary)'
              }}>{u.email}</span>

              <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{u.display_name}</span>

              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontFamily: "'Space Mono', monospace",
                fontSize: '9px',
                letterSpacing: '0.1em',
                color: statusColor(u.status),
                textTransform: 'uppercase'
              }}>
                <span style={{
                  width: '5px', height: '5px', borderRadius: '50%',
                  background: statusColor(u.status)
                }} />
                {u.status}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Provision modal */}
      {showModal && (
        <Modal title="PROVISION USER" onClose={() => setShowModal(false)}>
          <form onSubmit={handleProvision}>
            {formError && (
              <div style={{
                padding: '8px 12px',
                marginBottom: '16px',
                background: 'rgba(239,68,68,0.05)',
                border: '1px solid rgba(239,68,68,0.2)'
              }}>
                <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>
                  ✕ {formError}
                </span>
              </div>
            )}
            <div style={{ marginBottom: '16px' }}>
              <label style={labelStyle}>EMAIL</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>
            <div style={{ marginBottom: '16px' }}>
              <label style={labelStyle}>DISPLAY NAME</label>
              <input type="text" value={displayName} onChange={e => setDisplayName(e.target.value)} style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>USERNAME <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>(OPTIONAL)</span></label>
              <input type="text" value={username} onChange={e => setUsername(e.target.value)} style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>
            <button
              type="submit"
              disabled={submitting}
              style={{
                width: '100%',
                background: 'transparent',
                border: '1px solid var(--accent-cyan)',
                color: submitting ? 'var(--text-muted)' : 'var(--accent-cyan)',
                padding: '10px',
                fontSize: '11px',
                fontFamily: "'Space Mono', monospace",
                letterSpacing: '0.15em',
                textTransform: 'uppercase',
                cursor: submitting ? 'not-allowed' : 'pointer'
              }}
            >
              {submitting ? "PROVISIONING..." : "PROVISION USER"}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
