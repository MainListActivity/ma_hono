import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { createTenant, updateTenant, deleteTenant, listTenants, type TenantSummary } from "../api/client";
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

export default function TenantsPage() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Create modal
  const [showModal, setShowModal] = useState(false);
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Edit modal
  const [editTenant, setEditTenant] = useState<TenantSummary | null>(null);
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editStatus, setEditStatus] = useState<"active" | "disabled">("active");
  const [editIssuerUrl, setEditIssuerUrl] = useState("");
  const [editError, setEditError] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Delete confirm
  const [deletingTenant, setDeletingTenant] = useState<TenantSummary | null>(null);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);

  const load = async () => {
    if (!token) return;
    setLoading(true);
    setLoadError(null);
    try {
      const data = await listTenants(token);
      setTenants(data.tenants);
    } catch {
      setLoadError("FAILED TO LOAD TENANTS");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [token]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!slug.trim() || !displayName.trim()) {
      setFormError("ALL FIELDS REQUIRED");
      return;
    }
    setSubmitting(true);
    try {
      await createTenant(token!, slug.trim(), displayName.trim());
      setShowModal(false);
      setSlug("");
      setDisplayName("");
      await load();
    } catch {
      setFormError("FAILED — SLUG MAY ALREADY EXIST");
    } finally {
      setSubmitting(false);
    }
  };

  const openEdit = (t: TenantSummary, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditTenant(t);
    setEditDisplayName(t.display_name);
    setEditStatus(t.status);
    setEditIssuerUrl(t.issuer ?? "");
    setEditError(null);
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editTenant) return;
    setEditError(null);
    if (!editDisplayName.trim()) { setEditError("DISPLAY NAME REQUIRED"); return; }
    setEditSubmitting(true);
    try {
      await updateTenant(token!, editTenant.id, {
        display_name: editDisplayName.trim(),
        status: editStatus,
        primary_issuer_url: editIssuerUrl.trim() || undefined
      });
      setEditTenant(null);
      await load();
    } catch {
      setEditError("UPDATE FAILED");
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!deletingTenant) return;
    setDeleteSubmitting(true);
    try {
      await deleteTenant(token!, deletingTenant.id);
      setDeletingTenant(null);
      await load();
    } catch {
      setDeletingTenant(null);
    } finally {
      setDeleteSubmitting(false);
    }
  };

  return (
    <div>
      {/* Page header */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between',
        marginBottom: '28px',
        paddingBottom: '20px',
        borderBottom: '1px solid var(--border)'
      }}>
        <div>
          <div className="font-display" style={{
            fontSize: '10px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: 'var(--accent-cyan)',
            marginBottom: '6px'
          }}>
            PLATFORM / TENANTS
          </div>
          <h1 style={{
            margin: 0,
            fontSize: '22px',
            fontWeight: 300,
            color: 'var(--text-primary)',
            letterSpacing: '0.02em'
          }}>
            Tenant Registry
          </h1>
          <div style={{
            marginTop: '4px',
            fontSize: '12px',
            color: 'var(--text-muted)',
            fontFamily: "'Space Mono', monospace"
          }}>
            {loading ? '...' : `${tenants.length} RECORD${tenants.length !== 1 ? 'S' : ''}`}
          </div>
        </div>

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
          NEW TENANT
        </button>
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>
            LOADING...
          </span>
        </div>
      ) : loadError ? (
        <div style={{
          textAlign: 'center', padding: '40px 0',
          border: '1px solid rgba(239,68,68,0.3)',
          color: '#ef4444'
        }}>
          <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>
            ✕ {loadError}
          </span>
        </div>
      ) : tenants.length === 0 ? (
        <div style={{
          textAlign: 'center', padding: '60px 0',
          border: '1px dashed var(--border)',
          color: 'var(--text-muted)'
        }}>
          <div className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em', marginBottom: '8px' }}>
            NO RECORDS FOUND
          </div>
          <div style={{ fontSize: '13px' }}>Create your first tenant to get started</div>
        </div>
      ) : (
        <div style={{
          border: '1px solid var(--border)',
          background: 'var(--bg-surface)',
          overflow: 'hidden'
        }}>
          {/* Table header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1.2fr 90px 1.8fr 120px',
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-elevated)'
          }}>
            {['SLUG', 'DISPLAY NAME', 'STATUS', 'ISSUER URL', 'ACTIONS'].map(h => (
              <span key={h} className="font-display" style={{
                fontSize: '9px',
                letterSpacing: '0.15em',
                color: 'var(--text-dim)',
                textTransform: 'uppercase'
              }}>{h}</span>
            ))}
          </div>

          {/* Rows */}
          {tenants.map((t, i) => (
            <div
              key={t.id}
              onClick={() => navigate(`/tenants/${t.id}/users`)}
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1.2fr 90px 1.8fr 120px',
                padding: '12px 16px',
                borderBottom: i < tenants.length - 1 ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                transition: 'background 0.1s',
                alignItems: 'center'
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-elevated)'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = 'transparent'; }}
            >
              <span style={{
                fontFamily: "'Space Mono', monospace",
                fontSize: '12px',
                color: 'var(--accent-cyan)'
              }}>{t.slug}</span>

              <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{t.display_name}</span>

              <span style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                fontFamily: "'Space Mono', monospace",
                fontSize: '9px',
                letterSpacing: '0.1em',
                color: t.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)',
                textTransform: 'uppercase'
              }}>
                <span style={{
                  width: '5px', height: '5px', borderRadius: '50%',
                  background: t.status === 'active' ? 'var(--accent-green)' : 'var(--text-dim)'
                }} />
                {t.status}
              </span>

              <span style={{
                fontFamily: "'Space Mono', monospace",
                fontSize: '11px',
                color: 'var(--text-muted)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap'
              }}>{t.issuer ?? '—'}</span>

              <div style={{ display: 'flex', gap: '6px' }} onClick={e => e.stopPropagation()}>
                <button
                  onClick={e => openEdit(t, e)}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', padding: '4px 8px',
                    fontSize: '9px', fontFamily: "'Space Mono', monospace",
                    letterSpacing: '0.1em', cursor: 'pointer', textTransform: 'uppercase'
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent-cyan)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-cyan)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)'; }}
                >EDIT</button>
                <button
                  onClick={e => { e.stopPropagation(); setDeletingTenant(t); }}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', padding: '4px 8px',
                    fontSize: '9px', fontFamily: "'Space Mono', monospace",
                    letterSpacing: '0.1em', cursor: 'pointer', textTransform: 'uppercase'
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = '#ef4444'; (e.currentTarget as HTMLButtonElement).style.color = '#ef4444'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-muted)'; }}
                >DEL</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Edit modal */}
      {editTenant && (
        <Modal title={`EDIT — ${editTenant.slug}`} onClose={() => setEditTenant(null)}>
          <form onSubmit={handleEdit}>
            {editError && (
              <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {editError}</span>
              </div>
            )}
            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>DISPLAY NAME</label>
              <input type="text" value={editDisplayName} onChange={e => setEditDisplayName(e.target.value)} style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>
            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>STATUS</label>
              <select value={editStatus} onChange={e => setEditStatus(e.target.value as 'active' | 'disabled')} style={{ ...inputStyle, cursor: 'pointer' }}>
                <option value="active">active</option>
                <option value="disabled">disabled</option>
              </select>
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>PRIMARY ISSUER URL</label>
              <input type="text" value={editIssuerUrl} onChange={e => setEditIssuerUrl(e.target.value)}
                placeholder="https://o.example.com/t/slug" style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
              <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--text-muted)' }}>
                Use this to fix a wrong issuer URL. Should be <code style={{ fontFamily: "'Space Mono', monospace" }}>https://o.&#123;domain&#125;/t/&#123;slug&#125;</code>
              </div>
            </div>
            <button type="submit" disabled={editSubmitting} style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: editSubmitting ? 'var(--text-muted)' : 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: editSubmitting ? 'not-allowed' : 'pointer' }}>
              {editSubmitting ? 'SAVING...' : 'SAVE CHANGES'}
            </button>
          </form>
        </Modal>
      )}

      {/* Delete confirm modal */}
      {deletingTenant && (
        <Modal title="DELETE TENANT" onClose={() => setDeletingTenant(null)}>
          <div style={{ marginBottom: '20px', padding: '12px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '6px' }}>
              Delete <strong style={{ fontFamily: "'Space Mono', monospace", color: '#ef4444' }}>{deletingTenant.slug}</strong>?
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-muted)' }}>
              This will permanently delete the tenant and all associated users, clients, sessions, and credentials. This action cannot be undone.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={() => setDeletingTenant(null)} style={{ flex: 1, background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.12em', textTransform: 'uppercase', cursor: 'pointer' }}>
              CANCEL
            </button>
            <button onClick={handleDelete} disabled={deleteSubmitting} style={{ flex: 1, background: 'rgba(239,68,68,0.08)', border: '1px solid #ef4444', color: '#ef4444', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.12em', textTransform: 'uppercase', cursor: deleteSubmitting ? 'not-allowed' : 'pointer' }}>
              {deleteSubmitting ? 'DELETING...' : 'DELETE'}
            </button>
          </div>
        </Modal>
      )}

      {/* Create modal */}
      {showModal && (
        <Modal title="NEW TENANT" onClose={() => setShowModal(false)}>
          <form onSubmit={handleCreate}>
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
              <label style={labelStyle}>SLUG</label>
              <input
                type="text"
                value={slug}
                onChange={e => setSlug(e.target.value)}
                placeholder="acme"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>DISPLAY NAME</label>
              <input
                type="text"
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
                placeholder="Acme Corp"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
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
              {submitting ? "PROVISIONING..." : "CREATE TENANT"}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
