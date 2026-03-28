import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router";
import {
  getTenant,
  listClients,
  createClient,
  deleteClient,
  updateClient,
  getClient,
  updateClientAuthMethodPolicy,
  type TenantSummary,
  type ClientSummary,
  type AuthMethodPolicyWire
} from "../api/client";
import { useAuth } from "../App";
import Modal from "../components/Modal";
import AgentContextModal from "../components/AgentContextModal";

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

type ClientProfile = "spa" | "web" | "native";
type ClaimSourceType = "fixed" | "user_field";
type ClaimUserField = "id" | "email" | "email_verified" | "username" | "display_name";

interface ClaimEditorRow {
  id: string;
  claimName: string;
  sourceType: ClaimSourceType;
  fixedValue: string;
  userField: ClaimUserField;
}

const userFieldOptions: ClaimUserField[] = [
  "id",
  "email",
  "email_verified",
  "username",
  "display_name"
];

const profileLabel = (profile: ClientProfile) =>
  profile === "spa" ? "SPA" : profile === "web" ? "Web" : "Native";

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
  const [mfaRequired, setMfaRequired] = useState(false);

  const defaultPolicy = (): AuthMethodPolicyWire => ({
    password: { enabled: false, allow_registration: false },
    magic_link: { enabled: false, allow_registration: false },
    passkey: { enabled: false, allow_registration: false },
    google: { enabled: false },
    apple: { enabled: false },
    facebook: { enabled: false },
    wechat: { enabled: false },
    mfa_required: false
  });

  useEffect(() => {
    getClient(token, tenantId, client.client_id).then((c) => {
      const loadedPolicy = c.auth_method_policy ?? defaultPolicy();
      setPolicy(loadedPolicy);
      setMfaRequired(loadedPolicy.mfa_required ?? false);
    }).catch(() => setError("FAILED TO LOAD POLICY")).finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    if (!policy) return;
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await updateClientAuthMethodPolicy(token, tenantId, client.client_id, {
        ...policy,
        mfa_required: mfaRequired
      });
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
      <div style={{ marginBottom: '20px', paddingTop: '12px', borderTop: '1px solid var(--border)' }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
          <div>
            <label className="font-display" style={labelStyle}>Require MFA</label>
            <p style={{ fontSize: "11px", color: "var(--text-muted)", margin: 0 }}>
              Users without MFA enrolled will be prompted to enroll on next login
            </p>
          </div>
          <button
            type="button"
            onClick={() => setMfaRequired(v => !v)}
            style={{
              background: mfaRequired ? "var(--accent-cyan)" : "var(--bg-elevated)",
              border: `1px solid ${mfaRequired ? "var(--accent-cyan)" : "var(--border)"}`,
              color: mfaRequired ? "var(--bg-base)" : "var(--text-muted)",
              padding: "4px 12px", fontSize: "10px", fontFamily: "'Space Mono', monospace",
              cursor: "pointer", letterSpacing: "0.1em"
            }}
          >
            {mfaRequired ? "ON" : "OFF"}
          </button>
        </div>
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
  const [clientProfile, setClientProfile] = useState<ClientProfile>('web');
  const [redirectUris, setRedirectUris] = useState('');
  const [authMethod, setAuthMethod] = useState('client_secret_basic');
  const [accessTokenAudience, setAccessTokenAudience] = useState('');
  const [customClaims, setCustomClaims] = useState<ClaimEditorRow[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<{ clientId: string; secret: string | null } | null>(null);

  // Test login state
  const [testingClientId, setTestingClientId] = useState<string | null>(null);

  // Auth policy modal state
  const [policyClient, setPolicyClient] = useState<ClientSummary | null>(null);

  // Edit modal state
  const [editClient, setEditClient] = useState<ClientSummary | null>(null);
  const [editName, setEditName] = useState('');
  const [editProfile, setEditProfile] = useState<ClientProfile>('web');
  const [editRedirectUris, setEditRedirectUris] = useState('');
  const [editAuthMethod, setEditAuthMethod] = useState('');
  const [editAudience, setEditAudience] = useState('');
  const [editClaims, setEditClaims] = useState<ClaimEditorRow[]>([]);
  const [editError, setEditError] = useState<string | null>(null);
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Agent context modal state
  const [agentClient, setAgentClient] = useState<ClientSummary | null>(null);

  // Delete state
  const [deletingClientId, setDeletingClientId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ClientSummary | null>(null);

  const derivedApplicationType: "web" | "native" =
    clientProfile === "native" ? "native" : "web";
  const effectiveAuthMethod =
    clientProfile === "web" ? authMethod : "none";

  const resetCreateForm = () => {
    setShowCreate(false);
    setClientName('');
    setClientProfile('web');
    setRedirectUris('');
    setAuthMethod('client_secret_basic');
    setAccessTokenAudience('');
    setCustomClaims([]);
    setFormError(null);
  };

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
    const trimmedAudience = accessTokenAudience.trim();

    if (!clientName.trim() || uris.length === 0) {
      setFormError("CLIENT NAME AND AT LEAST ONE REDIRECT URI REQUIRED");
      return;
    }

    if (clientProfile === 'spa' && trimmedAudience.length === 0) {
      setFormError("SPA CLIENTS REQUIRE AN ACCESS TOKEN AUDIENCE");
      return;
    }

    for (const claim of customClaims) {
      if (!claim.claimName.trim()) {
        setFormError("EVERY CUSTOM CLAIM REQUIRES A CLAIM NAME");
        return;
      }
      if (claim.sourceType === 'fixed' && !claim.fixedValue.trim()) {
        setFormError("FIXED CLAIMS REQUIRE A VALUE");
        return;
      }
    }

    setSubmitting(true);
    try {
      const result = await createClient(token!, tenantId!, {
        client_name: clientName.trim(),
        client_profile: clientProfile,
        application_type: derivedApplicationType,
        redirect_uris: uris,
        token_endpoint_auth_method: effectiveAuthMethod,
        grant_types: ['authorization_code'],
        response_types: ['code'],
        ...(trimmedAudience ? { access_token_audience: trimmedAudience } : {}),
        ...(customClaims.length > 0
          ? {
              access_token_custom_claims: customClaims.map((claim) => ({
                claim_name: claim.claimName.trim(),
                source_type: claim.sourceType,
                ...(claim.sourceType === 'fixed'
                  ? { fixed_value: claim.fixedValue.trim() }
                  : { user_field: claim.userField })
              }))
            }
          : {})
      });
      resetCreateForm();
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

  const openEditModal = async (c: ClientSummary) => {
    setEditClient(c);
    setEditName(c.client_name);
    setEditProfile(c.client_profile);
    setEditRedirectUris(c.redirect_uris.join('\n'));
    setEditAuthMethod(c.token_endpoint_auth_method);
    setEditAudience(c.access_token_audience ?? '');
    setEditError(null);
    setEditSubmitting(false);
    try {
      const detail = await getClient(token!, tenantId!, c.client_id);
      setEditClaims(
        (detail.access_token_custom_claims ?? []).map((claim) => ({
          id: crypto.randomUUID(),
          claimName: claim.claim_name,
          sourceType: claim.source_type as ClaimSourceType,
          fixedValue: claim.fixed_value ?? '',
          userField: (claim.user_field ?? 'email') as ClaimUserField
        }))
      );
    } catch {
      setEditClaims([]);
    }
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEditError(null);
    if (!editClient) return;

    const uris = editRedirectUris.split('\n').map(u => u.trim()).filter(Boolean);
    const trimmedAudience = editAudience.trim();

    if (!editName.trim() || uris.length === 0) {
      setEditError("CLIENT NAME AND AT LEAST ONE REDIRECT URI REQUIRED");
      return;
    }

    if (editProfile === 'spa' && trimmedAudience.length === 0) {
      setEditError("SPA CLIENTS REQUIRE AN ACCESS TOKEN AUDIENCE");
      return;
    }

    for (const claim of editClaims) {
      if (!claim.claimName.trim()) {
        setEditError("EVERY CUSTOM CLAIM REQUIRES A CLAIM NAME");
        return;
      }
      if (claim.sourceType === 'fixed' && !claim.fixedValue.trim()) {
        setEditError("FIXED CLAIMS REQUIRE A VALUE");
        return;
      }
    }

    const editDerivedAppType: "web" | "native" = editProfile === "native" ? "native" : "web";
    const editEffectiveAuth = editProfile === "web" ? editAuthMethod : "none";

    setEditSubmitting(true);
    try {
      await updateClient(token!, tenantId!, editClient.client_id, {
        client_name: editName.trim(),
        client_profile: editProfile,
        application_type: editDerivedAppType,
        redirect_uris: uris,
        token_endpoint_auth_method: editEffectiveAuth,
        access_token_audience: trimmedAudience || null,
        access_token_custom_claims: editClaims.map((claim) => ({
          claim_name: claim.claimName.trim(),
          source_type: claim.sourceType,
          ...(claim.sourceType === 'fixed'
            ? { fixed_value: claim.fixedValue.trim() }
            : { user_field: claim.userField })
        }))
      });
      setEditClient(null);
      await load();
    } catch {
      setEditError("FAILED TO UPDATE CLIENT");
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleDelete = async (c: ClientSummary) => {
    setDeletingClientId(c.client_id);
    try {
      await deleteClient(token!, tenantId!, c.client_id);
      setConfirmDelete(null);
      await load();
    } catch {
      alert('Failed to delete client');
    } finally {
      setDeletingClientId(null);
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
          onClick={() => { resetCreateForm(); setShowCreate(true); }}
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
        <div style={{ border: '1px solid var(--border)', background: 'var(--bg-surface)', overflowX: 'auto' }}>
          {/* Table header */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 0.9fr 0.8fr 1fr 390px', padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)', minWidth: '1130px' }}>
            {['CLIENT NAME', 'CLIENT ID', 'PROFILE', 'TYPE', 'AUTH METHOD', 'ACTIONS'].map(h => (
              <span key={h} className="font-display" style={{ fontSize: '9px', letterSpacing: '0.15em', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{h}</span>
            ))}
          </div>

          {clients.map((c, i) => (
            <div key={c.id} style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 0.9fr 0.8fr 1fr 390px', padding: '12px 16px', borderBottom: i < clients.length - 1 ? '1px solid var(--border)' : 'none', alignItems: 'center', minWidth: '1130px' }}>
              <div>
                <div style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '2px' }}>{c.client_name}</div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace" }}>
                  {c.redirect_uris.length} redirect URI{c.redirect_uris.length !== 1 ? 's' : ''}
                </div>
                {c.access_token_audience && (
                  <div style={{ fontSize: '10px', color: 'var(--accent-amber, #fbbf24)', fontFamily: "'Space Mono', monospace", marginTop: '4px' }}>
                    AUD {c.access_token_audience}
                  </div>
                )}
              </div>
              <span style={{ ...monoStyle, color: 'var(--accent-cyan)', fontSize: '11px' }}>{c.client_id}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ ...monoStyle, fontSize: '11px' }}>{profileLabel(c.client_profile)}</span>
                {(c.access_token_custom_claims_count ?? 0) > 0 && (
                  <span style={{ fontSize: '9px', color: 'var(--accent-amber, #fbbf24)', border: '1px solid rgba(251,191,36,0.35)', padding: '2px 6px', fontFamily: "'Space Mono', monospace" }}>
                    {c.access_token_custom_claims_count} CLAIM{c.access_token_custom_claims_count === 1 ? '' : 'S'}
                  </span>
                )}
              </div>
              <span style={{ ...monoStyle, fontSize: '11px' }}>{c.application_type}</span>
              <span style={{ ...monoStyle, fontSize: '11px' }}>{c.token_endpoint_auth_method}</span>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
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
                <button
                  onClick={() => openEditModal(c)}
                  style={{ ...btnStyle('var(--accent-cyan)'), padding: '5px 10px' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(0,229,255,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  EDIT
                </button>
                <button
                  onClick={() => setAgentClient(c)}
                  style={{ ...btnStyle('var(--accent-blue, #3b82f6)'), padding: '5px 10px' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(59,130,246,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  AGENT
                </button>
                <button
                  onClick={() => setConfirmDelete(c)}
                  style={{ ...btnStyle('#ef4444'), padding: '5px 10px' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(239,68,68,0.08)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                >
                  DEL
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <Modal title="NEW OIDC CLIENT" onClose={resetCreateForm}>
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
              <label style={labelStyle}>CLIENT PROFILE</label>
              <select
                value={clientProfile}
                onChange={e => {
                  const profile = e.target.value as ClientProfile;
                  setClientProfile(profile);
                  if (profile === 'web') {
                    setAuthMethod(current => current === 'none' ? 'client_secret_basic' : current);
                    return;
                  }
                  setAuthMethod('none');
                }}
                style={{ ...inputStyle, cursor: 'pointer' }}
              >
                <option value="web">web</option>
                <option value="spa">spa</option>
                <option value="native">native</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>APPLICATION TYPE</label>
              <select value={derivedApplicationType} disabled style={{ ...inputStyle, cursor: 'not-allowed', opacity: 0.7 }}>
                <option value="web">web</option>
                <option value="native">native</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>TOKEN ENDPOINT AUTH METHOD</label>
              <select
                value={effectiveAuthMethod}
                onChange={e => setAuthMethod(e.target.value)}
                disabled={clientProfile !== 'web'}
                style={{ ...inputStyle, cursor: clientProfile === 'web' ? 'pointer' : 'not-allowed', opacity: clientProfile === 'web' ? 1 : 0.7 }}
              >
                {clientProfile !== 'web' && <option value="none">none</option>}
                {clientProfile === 'web' && <option value="client_secret_basic">client_secret_basic</option>}
                {clientProfile === 'web' && <option value="client_secret_post">client_secret_post</option>}
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>
                ACCESS TOKEN AUDIENCE{clientProfile === 'spa' ? ' (required)' : ''}
              </label>
              <input
                type="text"
                value={accessTokenAudience}
                onChange={e => setAccessTokenAudience(e.target.value)}
                placeholder="https://api.example.com"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>REDIRECT URIS (one per line, prefix regex: for pattern matching)</label>
              <textarea
                value={redirectUris}
                onChange={e => setRedirectUris(e.target.value)}
                placeholder={"https://myapp.example.com/callback\nregex:https://.*\\.example\\.com/callback"}
                rows={3}
                style={{ ...inputStyle, resize: 'vertical' as const, lineHeight: '1.5' }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <div style={{ marginBottom: '20px', padding: '14px', border: '1px solid var(--border)', background: 'var(--bg-surface)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div>
                  <label style={labelStyle}>CUSTOM ACCESS TOKEN CLAIMS</label>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Fixed values or user field mappings appended to the access token.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setCustomClaims((current) => [
                    ...current,
                    {
                      id: crypto.randomUUID(),
                      claimName: '',
                      sourceType: 'fixed',
                      fixedValue: '',
                      userField: 'email'
                    }
                  ])}
                  style={{ ...btnStyle('var(--accent-amber, #fbbf24)'), padding: '5px 10px' }}
                >
                  + CLAIM
                </button>
              </div>

              {customClaims.length === 0 ? (
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'Space Mono', monospace" }}>
                  NO CUSTOM CLAIMS
                </div>
              ) : (
                <div style={{ display: 'grid', gap: '10px' }}>
                  {customClaims.map((claim) => (
                    <div key={claim.id} style={{ border: '1px solid var(--border)', padding: '12px', background: 'var(--bg-base)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr auto', gap: '10px', marginBottom: '10px' }}>
                        <input
                          type="text"
                          value={claim.claimName}
                          onChange={e => setCustomClaims((current) => current.map((row) => row.id === claim.id ? { ...row, claimName: e.target.value } : row))}
                          placeholder="claim name"
                          style={inputStyle}
                        />
                        <select
                          value={claim.sourceType}
                          onChange={e => setCustomClaims((current) => current.map((row) => row.id === claim.id ? { ...row, sourceType: e.target.value as ClaimSourceType } : row))}
                          style={{ ...inputStyle, cursor: 'pointer' }}
                        >
                          <option value="fixed">fixed value</option>
                          <option value="user_field">user field</option>
                        </select>
                        <button
                          type="button"
                          onClick={() => setCustomClaims((current) => current.filter((row) => row.id !== claim.id))}
                          style={{ ...btnStyle('#ef4444'), padding: '6px 10px' }}
                        >
                          REMOVE
                        </button>
                      </div>

                      {claim.sourceType === 'fixed' ? (
                        <input
                          type="text"
                          value={claim.fixedValue}
                          onChange={e => setCustomClaims((current) => current.map((row) => row.id === claim.id ? { ...row, fixedValue: e.target.value } : row))}
                          placeholder="fixed value"
                          style={inputStyle}
                        />
                      ) : (
                        <select
                          value={claim.userField}
                          onChange={e => setCustomClaims((current) => current.map((row) => row.id === claim.id ? { ...row, userField: e.target.value as ClaimUserField } : row))}
                          style={{ ...inputStyle, cursor: 'pointer' }}
                        >
                          {userFieldOptions.map((option) => (
                            <option key={option} value={option}>{option}</option>
                          ))}
                        </select>
                      )}
                    </div>
                  ))}
                </div>
              )}
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

      {/* Delete confirmation modal */}
      {confirmDelete && (
        <Modal title="DELETE CLIENT" onClose={() => setConfirmDelete(null)}>
          <div style={{ marginBottom: '16px', padding: '10px 14px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.3)' }}>
            <span className="font-display" style={{ fontSize: '9px', letterSpacing: '0.12em', color: '#ef4444' }}>
              THIS ACTION CANNOT BE UNDONE
            </span>
          </div>
          <div style={{ marginBottom: '16px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            Delete <strong style={{ color: 'var(--text-primary)' }}>{confirmDelete.client_name}</strong> and all associated
            configuration including auth method policies and custom access token claims?
          </div>
          <div style={{ marginBottom: '20px' }}>
            <label style={labelStyle}>CLIENT ID</label>
            <div style={{ ...monoStyle, color: 'var(--accent-cyan)', fontSize: '12px', padding: '8px 12px', background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
              {confirmDelete.client_id}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              onClick={() => setConfirmDelete(null)}
              style={{ flex: 1, background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: 'pointer' }}
            >
              CANCEL
            </button>
            <button
              onClick={() => handleDelete(confirmDelete)}
              disabled={deletingClientId === confirmDelete.client_id}
              style={{ flex: 1, background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', color: '#ef4444', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: deletingClientId === confirmDelete.client_id ? 'not-allowed' : 'pointer' }}
            >
              {deletingClientId === confirmDelete.client_id ? 'DELETING...' : 'DELETE'}
            </button>
          </div>
        </Modal>
      )}

      {/* Edit client modal */}
      {editClient && (
        <Modal title="EDIT OIDC CLIENT" onClose={() => setEditClient(null)}>
          <form onSubmit={handleEdit}>
            {editError && (
              <div style={{ padding: '8px 12px', marginBottom: '16px', background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <span className="font-display" style={{ fontSize: '10px', color: '#ef4444', letterSpacing: '0.08em' }}>✕ {editError}</span>
              </div>
            )}

            <div style={{ marginBottom: '10px' }}>
              <label style={labelStyle}>CLIENT ID</label>
              <div style={{ ...monoStyle, color: 'var(--accent-cyan)', fontSize: '12px', padding: '8px 12px', background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
                {editClient.client_id}
              </div>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>CLIENT NAME</label>
              <input type="text" value={editName} onChange={e => setEditName(e.target.value)} style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')} />
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>CLIENT PROFILE</label>
              <select
                value={editProfile}
                onChange={e => {
                  const profile = e.target.value as ClientProfile;
                  setEditProfile(profile);
                  if (profile === 'web') {
                    setEditAuthMethod(current => current === 'none' ? 'client_secret_basic' : current);
                    return;
                  }
                  setEditAuthMethod('none');
                }}
                style={{ ...inputStyle, cursor: 'pointer' }}
              >
                <option value="web">web</option>
                <option value="spa">spa</option>
                <option value="native">native</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>APPLICATION TYPE</label>
              <select value={editProfile === "native" ? "native" : "web"} disabled style={{ ...inputStyle, cursor: 'not-allowed', opacity: 0.7 }}>
                <option value="web">web</option>
                <option value="native">native</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>TOKEN ENDPOINT AUTH METHOD</label>
              <select
                value={editProfile === 'web' ? editAuthMethod : 'none'}
                onChange={e => setEditAuthMethod(e.target.value)}
                disabled={editProfile !== 'web'}
                style={{ ...inputStyle, cursor: editProfile === 'web' ? 'pointer' : 'not-allowed', opacity: editProfile === 'web' ? 1 : 0.7 }}
              >
                {editProfile !== 'web' && <option value="none">none</option>}
                {editProfile === 'web' && <option value="client_secret_basic">client_secret_basic</option>}
                {editProfile === 'web' && <option value="client_secret_post">client_secret_post</option>}
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={labelStyle}>
                ACCESS TOKEN AUDIENCE{editProfile === 'spa' ? ' (required)' : ''}
              </label>
              <input
                type="text"
                value={editAudience}
                onChange={e => setEditAudience(e.target.value)}
                placeholder="https://api.example.com"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={labelStyle}>REDIRECT URIS (one per line, prefix regex: for pattern matching)</label>
              <textarea
                value={editRedirectUris}
                onChange={e => setEditRedirectUris(e.target.value)}
                rows={3}
                style={{ ...inputStyle, resize: 'vertical' as const, lineHeight: '1.5' }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent-cyan)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border)')}
              />
            </div>

            <div style={{ marginBottom: '20px', padding: '14px', border: '1px solid var(--border)', background: 'var(--bg-surface)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div>
                  <label style={labelStyle}>CUSTOM ACCESS TOKEN CLAIMS</label>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Fixed values or user field mappings appended to the access token.
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setEditClaims((current) => [
                    ...current,
                    {
                      id: crypto.randomUUID(),
                      claimName: '',
                      sourceType: 'fixed',
                      fixedValue: '',
                      userField: 'email'
                    }
                  ])}
                  style={{ ...btnStyle('var(--accent-amber, #fbbf24)'), padding: '5px 10px' }}
                >
                  + CLAIM
                </button>
              </div>

              {editClaims.length === 0 ? (
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'Space Mono', monospace" }}>
                  NO CUSTOM CLAIMS
                </div>
              ) : (
                <div style={{ display: 'grid', gap: '10px' }}>
                  {editClaims.map((claim) => (
                    <div key={claim.id} style={{ border: '1px solid var(--border)', padding: '12px', background: 'var(--bg-base)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr auto', gap: '10px', marginBottom: '10px' }}>
                        <input
                          type="text"
                          value={claim.claimName}
                          onChange={e => setEditClaims((current) => current.map((row) => row.id === claim.id ? { ...row, claimName: e.target.value } : row))}
                          placeholder="claim name"
                          style={inputStyle}
                        />
                        <select
                          value={claim.sourceType}
                          onChange={e => setEditClaims((current) => current.map((row) => row.id === claim.id ? { ...row, sourceType: e.target.value as ClaimSourceType } : row))}
                          style={{ ...inputStyle, cursor: 'pointer' }}
                        >
                          <option value="fixed">fixed value</option>
                          <option value="user_field">user field</option>
                        </select>
                        <button
                          type="button"
                          onClick={() => setEditClaims((current) => current.filter((row) => row.id !== claim.id))}
                          style={{ ...btnStyle('#ef4444'), padding: '6px 10px' }}
                        >
                          REMOVE
                        </button>
                      </div>

                      {claim.sourceType === 'fixed' ? (
                        <input
                          type="text"
                          value={claim.fixedValue}
                          onChange={e => setEditClaims((current) => current.map((row) => row.id === claim.id ? { ...row, fixedValue: e.target.value } : row))}
                          placeholder="fixed value"
                          style={inputStyle}
                        />
                      ) : (
                        <select
                          value={claim.userField}
                          onChange={e => setEditClaims((current) => current.map((row) => row.id === claim.id ? { ...row, userField: e.target.value as ClaimUserField } : row))}
                          style={{ ...inputStyle, cursor: 'pointer' }}
                        >
                          {userFieldOptions.map((option) => (
                            <option key={option} value={option}>{option}</option>
                          ))}
                        </select>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <button type="submit" disabled={editSubmitting} style={{ width: '100%', background: 'transparent', border: '1px solid var(--accent-cyan)', color: editSubmitting ? 'var(--text-muted)' : 'var(--accent-cyan)', padding: '10px', fontSize: '11px', fontFamily: "'Space Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', cursor: editSubmitting ? 'not-allowed' : 'pointer' }}>
              {editSubmitting ? 'SAVING...' : 'SAVE CHANGES'}
            </button>
          </form>
        </Modal>
      )}

      {/* Agent context modal */}
      {agentClient && tenant && (
        <AgentContextModal
          tenant={tenant}
          client={agentClient}
          onClose={() => setAgentClient(null)}
        />
      )}
    </div>
  );
}
