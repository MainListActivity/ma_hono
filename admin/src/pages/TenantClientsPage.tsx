import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router";
import {
  getTenant,
  listClients,
  createClient,
  getClient,
  updateClientAuthMethodPolicy,
  type TenantSummary,
  type ClientSummary,
  type AuthMethodPolicyWire
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

const monoStyle: React.CSSProperties = {
  fontFamily: "'Space Mono', monospace",
  fontSize: '11px',
  color: 'var(--text-dim)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap' as const
};

// Build a PKCE code_challenge from a verifier (SHA-256 / base64url)
async function buildPkce(): Promise<{ verifier: string; challenge: string }> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const verifier = btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return { verifier, challenge };
}

// Derive the authorize URL from the tenant's issuer.
// issuer is like "https://o.maplayer.top/t/map" → authorize at that URL + "/authorize"
// but since the SPA lives on auth.maplayer.top and cannot reach /t/:tenant/authorize there,
// we use the issuer URL directly which already points to o.{domain}.
function buildAuthorizeUrl(
  issuer: string,
  clientId: string,
  redirectUri: string,
  challenge: string,
  state: string
): string {
  const url = new URL(`${issuer}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

function AuthMethodPolicyModal({
  token,
  tenantId,
  client,
  onClose
}: {
  token: string;
  tenantId: string;
  client: ClientSummary;
  onClose: () => void;
}) {
  const [policy, setPolicy] = useState<AuthMethodPolicyWire | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const defaultPolicy = (): AuthMethodPolicyWire => ({
    password: { enabled: false, allow_registration: false },
    magic_link: { enabled: false, allow_registration: false },
    passkey: { enabled: false, allow_registration: false },
    google: { enabled: false },
    apple: { enabled: false },
    facebook: { enabled: false },
    wechat: { enabled: false }
  });

  useEffect(() => {
    getClient(token, tenantId, client.client_id).then((c) => {
      setPolicy(c.auth_method_policy ?? defaultPolicy());
    }).catch(() => setError("FAILED TO LOAD POLICY")).finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    if (!policy) return;
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await updateClientAuthMethodPolicy(token, tenantId, client.client_id, policy);
      setSaved(true);
    } catch {
      setError("FAILED TO SAVE");
    } finally {
      setSaving(false);
    }
  };

  const toggleStyle = (active: boolean): React.CSSProperties => ({
    display: 'inline-block',
    width: '36px',
    height: '18px',
    background: active ? 'var(--accent-cyan)' : 'var(--bg-elevated)',
    border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`,
    cursor: 'pointer',
    position: 'relative',
    transition: 'all 0.15s',
    verticalAlign: 'middle'
  });

  const knobStyle = (active: boolean): React.CSSProperties => ({
    position: 'absolute',
    top: '2px',
    left: active ? '18px' : '2px',
    width: '12px',
    height: '12px',
    background: active ? 'var(--bg-base)' : 'var(--text-muted)',
    transition: 'left 0.15s'
  });

  const Toggle = ({ active, onChange }: { active: boolean; onChange: (v: boolean) => void }) => (
    <button
      type="button"
      onClick={() => onChange(!active)}
      style={toggleStyle(active)}
      aria-label={active ? "enabled" : "disabled"}
    >
      <div style={knobStyle(active)} />
    </button>
  );

  if (loading) {
    return (
      <Modal title={`AUTH METHOD POLICY — ${client.client_name}`} onClose={onClose}>
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace", fontSize: '11px' }}>LOADING...</div>
      </Modal>
    );
  }

  const methods: { key: keyof AuthMethodPolicyWire; label: string; hasReg: boolean }[] = [
    { key: 'password', label: 'Password', hasReg: true },
    { key: 'magic_link', label: 'Magic Link', hasReg: true },
    { key: 'passkey', label: 'Passkey', hasReg: true },
    { key: 'google', label: 'Google', hasReg: false },
    { key: 'apple', label: 'Apple', hasReg: false },
    { key: 'facebook', label: 'Facebook', hasReg: false },
    { key: 'wechat', label: 'WeChat', hasReg: false }
  ];

  return (
    <Modal title={`AUTH METHOD POLICY — ${client.client_name}`} onClose={onClose}>
      {error && (
        <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {error}</span>
        </div>
      )}
      {saved && (
        <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(0,229,128,0.05)', border: '1px solid rgba(0,229,128,0.2)' }}>
          <span className="font-display" style={{ fontSize: '10px', color: 'var(--accent-green)', letterSpacing: '0.08em' }}>✓ SAVED</span>
        </div>
      )}
      <div style={{ marginBottom: '20px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1.5fr', padding: '6px 0', borderBottom: '1px solid var(--border)', marginBottom: '8px' }}>
          {['METHOD', 'ENABLED', 'ALLOW REG.'].map(h => (
            <span key={h} className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-dim)' }}>{h}</span>
          ))}
        </div>
        {policy && methods.map(({ key, label, hasReg }, i) => {
          const val = policy[key] as { enabled: boolean; allow_registration?: boolean };
          return (
            <div key={key}>
              {i === 3 && <div style={{ borderTop: '1px solid var(--border)', margin: '8px 0' }} />}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1.5fr', padding: '6px 0', alignItems: 'center' }}>
                <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{label}</span>
                <Toggle
                  active={val.enabled}
                  onChange={(v) => setPolicy({ ...policy, [key]: { ...val, enabled: v } })}
                />
                {hasReg ? (
                  <Toggle
                    active={val.allow_registration ?? false}
                    onChange={(v) => setPolicy({ ...policy, [key]: { ...val, allow_registration: v } })}
                  />
                ) : (
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'Space Mono', monospace" }}>—</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <button
        type="button"
        onClick={handleSave}
        disabled={saving}
        style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: saving ? 'var(--text-muted)' : 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: saving ? 'not-allowed' : 'pointer' }}
      >
        {saving ? 'SAVING...' : 'SAVE'}
      </button>
    </Modal>
  );
}

export default function TenantClientsPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { token } = useAuth();
  const navigate = useNavigate();
  const [tenant, setTenant] = useState<TenantSummary | null>(null);
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Create modal state
  const [showCreate, setShowCreate] = useState(false);
  const [clientName, setClientName] = useState('');
  const [appType, setAppType] = useState<'web' | 'native'>('native');
  const [redirectUris, setRedirectUris] = useState('');
  const [authMethod, setAuthMethod] = useState('none');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<{ clientId: string; secret: string | null } | null>(null);

  // Test login state
  const [testingClientId, setTestingClientId] = useState<string | null>(null);

  // Auth policy modal state
  const [policyClient, setPolicyClient] = useState<ClientSummary | null>(null);

  const load = async () => {
    if (!token || !tenantId) return;
    setLoading(true);
    setLoadError(null);
    try {
      const [t, c] = await Promise.all([
        getTenant(token, tenantId),
        listClients(token, tenantId)
      ]);
      setTenant(t);
      setClients(c.clients);
    } catch {
      setLoadError("FAILED TO LOAD");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [token, tenantId]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const uris = redirectUris.split('\n').map(u => u.trim()).filter(Boolean);
    if (!clientName.trim() || uris.length === 0) {
      setFormError("CLIENT NAME AND AT LEAST ONE REDIRECT URI REQUIRED");
      return;
    }
    setSubmitting(true);
    try {
      const result = await createClient(token!, tenantId!, {
        client_name: clientName.trim(),
        application_type: appType,
        redirect_uris: uris,
        token_endpoint_auth_method: authMethod,
        grant_types: ['authorization_code'],
        response_types: ['code']
      });
      setShowCreate(false);
      setClientName('');
      setRedirectUris('');
      setAppType('native');
      setAuthMethod('none');
      if (result.client_secret) {
        setCreatedSecret({ clientId: result.client_id, secret: result.client_secret });
      }
      await load();
    } catch {
      setFormError("FAILED TO CREATE CLIENT");
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestLogin = async (client: ClientSummary) => {
    if (!tenant?.issuer) {
      alert('Tenant has no issuer configured.');
      return;
    }
    const firstUri = client.redirect_uris[0];
    if (!firstUri) {
      alert('Client has no redirect URIs.');
      return;
    }
    setTestingClientId(client.client_id);
    try {
      const state = crypto.randomUUID();
      const { challenge } = await buildPkce();
      const authorizeUrl = buildAuthorizeUrl(tenant.issuer, client.client_id, firstUri, challenge, state);
      window.open(authorizeUrl, '_blank');
    } finally {
      setTestingClientId(null);
    }
  };

  const btnStyle = (accent = 'var(--accent-cyan)'): React.CSSProperties => ({
    background: 'transparent',
    border: `1px solid ${accent}`,
    color: accent,
    padding: '6px 14px',
    fontSize: '10px',
    fontFamily: "'Space Mono', monospace",
    letterSpacing: '0.1em',
    textTransform: 'uppercase' as const,
    cursor: 'pointer',
    whiteSpace: 'nowrap' as const
  });

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '28px', paddingBottom: '20px', borderBottom: '1px solid var(--border)' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <button
              onClick={() => navigate(`/tenants/${tenantId}/users`)}
              style={{ ...btnStyle('var(--text-muted)'), padding: '3px 8px', fontSize: '9px' }}
            >
              ← USERS
            </button>
            <span className="font-display" style={{ fontSize: '10px', letterSpacing: '0.2em', textTransform: 'uppercase', color: 'var(--accent-cyan)' }}>
              {tenant?.slug ?? tenantId} / CLIENTS
            </span>
          </div>
          <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 300, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
            OIDC Clients
          </h1>
          <div style={{ marginTop: '4px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace" }}>
            {loading ? '...' : `${clients.length} RECORD${clients.length !== 1 ? 'S' : ''}`}
          </div>
        </div>
        <button
          onClick={() => { setShowCreate(true); setFormError(null); }}
          style={{ ...btnStyle(), padding: '8px 16px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}
          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,229,255,0.08)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
        >
          <span style={{ fontSize: '14px' }}>+</span> NEW CLIENT
        </button>
      </div>

      {/* Issuer info */}
      {tenant?.issuer && (
        <div style={{ marginBottom: '20px', padding: '10px 14px', background: 'var(--bg-surface)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-muted)' }}>ISSUER</span>
          <span style={{ ...monoStyle, color: 'var(--text-secondary)', fontSize: '12px' }}>{tenant.issuer}</span>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
          <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>LOADING...</span>
        </div>
      ) : loadError ? (
        <div style={{ textAlign: 'center', padding: '40px 0', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
          <span className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em' }}>✕ {loadError}</span>
        </div>
      ) : clients.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 0', border: '1px dashed var(--border)', color: 'var(--text-muted)' }}>
          <div className="font-display" style={{ fontSize: '11px', letterSpacing: '0.12em', marginBottom: '8px' }}>NO CLIENTS</div>
          <div style={{ fontSize: '13px' }}>Create a client to start an OIDC authorization flow</div>
        </div>
      ) : (
        <div style={{ border: '1px solid var(--border)', background: 'var(--bg-surface)', overflow: 'hidden' }}>
          {/* Table header */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1fr 1fr 220px', padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
            {['CLIENT NAME', 'CLIENT ID', 'TYPE', 'AUTH METHOD', 'ACTIONS'].map(h => (
              <span key={h} className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{h}</span>
            ))}
          </div>

          {clients.map((c, i) => (
            <div key={c.id} style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1fr 1fr 220px', padding: '12px 16px', borderBottom: i < clients.length - 1 ? '1px solid var(--border)' : 'none', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '2px' }}>{c.client_name}</div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace" }}>
                  {c.redirect_uris.length} redirect URI{c.redirect_uris.length !== 1 ? 's' : ''}
                </div>
              </div>
              <span style={{ ...monoStyle, color: 'var(--accent-cyan)', fontSize: '11px' }}>{c.client_id}</span>
              <span style={{ ...monoStyle, fontSize: '11px' }}>{c.application_type}</span>
              <span style={{ ...monoStyle, fontSize: '11px' }}>{c.token_endpoint_auth_method}</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  onClick={() => handleTestLogin(c)}
                  disabled={testingClientId === c.client_id}
                  style={{ ...btnStyle('var(--accent-green)'), padding: '5px 10px' }}
                  title={`Open authorize URL for ${c.client_id} in a new tab`}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,229,128,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  {testingClientId === c.client_id ? '...' : '▶ TEST'}
                </button>
                <button
                  onClick={() => setPolicyClient(c)}
                  style={{ ...btnStyle('var(--accent-amber, #fbbf24)'), padding: '5px 10px' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(251,191,36,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  AUTH
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <Modal title="NEW OIDC CLIENT" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleCreate}>
            {formError && (
              <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {formError}</span>
              </div>
            )}

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>CLIENT NAME</label>
              <input type="text" value={clientName} onChange={e => setClientName(e.target.value)} placeholder="My App" style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>APPLICATION TYPE</label>
              <select value={appType} onChange={e => {
                const v = e.target.value as 'web' | 'native';
                setAppType(v);
                if (v === 'native') setAuthMethod('none');
                else setAuthMethod('client_secret_basic');
              }} style={{ ...inputStyle, cursor: 'pointer' }}>
                <option value="native">native (public client, no secret)</option>
                <option value="web">web (confidential client)</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>TOKEN ENDPOINT AUTH METHOD</label>
              <select value={authMethod} onChange={e => setAuthMethod(e.target.value)} style={{ ...inputStyle, cursor: 'pointer' }}>
                {appType === 'native' && <option value="none">none</option>}
                {appType === 'web' && <option value="client_secret_basic">client_secret_basic</option>}
                {appType === 'web' && <option value="client_secret_post">client_secret_post</option>}
              </select>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>REDIRECT URIS (one per line)</label>
              <textarea
                value={redirectUris}
                onChange={e => setRedirectUris(e.target.value)}
                placeholder={"https://myapp.example.com/callback\nhttps://localhost:3000/callback"}
                rows={3}
                style={{ ...inputStyle, resize: 'vertical' as const, lineHeight: '1.5' }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <button type="submit" disabled={submitting} style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: submitting ? 'var(--text-muted)' : 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: submitting ? 'not-allowed' : 'pointer' }}>
              {submitting ? 'CREATING...' : 'CREATE CLIENT'}
            </button>
          </form>
        </Modal>
      )}

      {/* Auth method policy modal */}
      {policyClient && (
        <AuthMethodPolicyModal
          token={token!}
          tenantId={tenantId!}
          client={policyClient}
          onClose={() => setPolicyClient(null)}
        />
      )}

      {/* Created secret modal */}
      {createdSecret && (
        <Modal title="CLIENT CREATED" onClose={() => setCreatedSecret(null)}>
          <div style={{ marginBottom: '16px', padding: '10px 14px', background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.3)' }}>
            <span className="font-display" style={{ fontSize: '9px', letterSpacing: '0.12em', color: '#fbbf24' }}>
              COPY THE SECRET NOW — IT WILL NOT BE SHOWN AGAIN
            </span>
          </div>
          <div style={{ marginBottom: '12px' }}>
            <label style={labelStyle}>CLIENT ID</label>
            <div style={{ ...monoStyle, color: 'var(--accent-cyan)', fontSize: '12px', padding: '8px 12px', background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
              {createdSecret.clientId}
            </div>
          </div>
          {createdSecret.secret && (
            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>CLIENT SECRET</label>
              <div style={{ ...monoStyle, color: 'var(--accent-amber, #fbbf24)', fontSize: '12px', padding: '8px 12px', background: 'var(--bg-base)', border: '1px solid rgba(251,191,36,0.3)', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                {createdSecret.secret}
              </div>
            </div>
          )}
          <button onClick={() => setCreatedSecret(null)} style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: 'pointer' }}>
            I HAVE SAVED THE SECRET
          </button>
        </Modal>
      )}
    </div>
  );
}
