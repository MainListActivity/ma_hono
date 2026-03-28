import { useState } from "react";
import type { ClientSummary, TenantSummary } from "../api/client";

// ─── Agent context templates ────────────────────────────────────────────────
// Placeholders: {{issuer}}, {{client_id}}, {{redirect_uri}}, {{audience}},
//               {{authorize_endpoint}}, {{token_endpoint}}, {{jwks_uri}},
//               {{userinfo_endpoint}}, {{discovery_url}}
// Secret-sensitive values use environment variable references.

const spaTemplate = `# OIDC SPA Client Integration

## Identity Provider

This application authenticates users via an OpenID Connect provider.

- **Issuer:** \`{{issuer}}\`
- **Discovery:** \`{{discovery_url}}\`
- **JWKS:** \`{{jwks_uri}}\`

## Client Configuration

| Field | Value |
|---|---|
| Client ID | \`{{client_id}}\` |
| Redirect URI | \`{{redirect_uri}}\` |
| Grant Type | \`authorization_code\` |
| Response Type | \`code\` |
| PKCE | Required (S256) |
| Token Auth | None (public client) |
| Audience | \`{{audience}}\` |

## Endpoints

| Endpoint | URL |
|---|---|
| Authorization | \`{{authorize_endpoint}}\` |
| Token | \`{{token_endpoint}}\` |
| UserInfo | \`{{userinfo_endpoint}}\` |

## Integration Notes

- This is a **public SPA client** — no client secret is used.
- **PKCE is mandatory.** Generate a \`code_verifier\`, derive a SHA-256 \`code_challenge\`, and include \`code_challenge_method=S256\` in the authorize request.
- The access token audience is \`{{audience}}\` — validate this in your resource server.
- Tokens are signed JWTs. Verify signatures using keys from the JWKS endpoint.
- Use \`openid\` as the minimum scope. Add \`profile\`, \`email\` as needed.

## Example Authorization Request

\`\`\`
{{authorize_endpoint}}?
  response_type=code&
  client_id={{client_id}}&
  redirect_uri={{redirect_uri}}&
  scope=openid&
  code_challenge=<BASE64URL_SHA256_OF_VERIFIER>&
  code_challenge_method=S256&
  state=<RANDOM_STATE>
\`\`\`

## Example Token Exchange

\`\`\`bash
curl -X POST {{token_endpoint}} \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=<AUTH_CODE>" \\
  -d "redirect_uri={{redirect_uri}}" \\
  -d "client_id={{client_id}}" \\
  -d "code_verifier=<CODE_VERIFIER>"
\`\`\`
`;

const webTemplate = `# OIDC Web Client Integration

## Identity Provider

This application authenticates users via an OpenID Connect provider.

- **Issuer:** \`{{issuer}}\`
- **Discovery:** \`{{discovery_url}}\`
- **JWKS:** \`{{jwks_uri}}\`

## Client Configuration

| Field | Value |
|---|---|
| Client ID | \`{{client_id}}\` |
| Client Secret | \`\${OIDC_CLIENT_SECRET}\` |
| Redirect URI | \`{{redirect_uri}}\` |
| Grant Type | \`authorization_code\` |
| Response Type | \`code\` |
| PKCE | Recommended (S256) |
| Token Auth | \`client_secret_basic\` |

## Environment Variables

\`\`\`bash
OIDC_CLIENT_ID={{client_id}}
OIDC_CLIENT_SECRET=<your-client-secret>
OIDC_ISSUER={{issuer}}
OIDC_REDIRECT_URI={{redirect_uri}}
\`\`\`

## Endpoints

| Endpoint | URL |
|---|---|
| Authorization | \`{{authorize_endpoint}}\` |
| Token | \`{{token_endpoint}}\` |
| UserInfo | \`{{userinfo_endpoint}}\` |

## Integration Notes

- This is a **confidential web client** — the client secret must be kept server-side.
- Token requests use HTTP Basic authentication: \`Authorization: Basic base64(client_id:client_secret)\`.
- PKCE is recommended even for confidential clients.
- Tokens are signed JWTs. Verify signatures using keys from the JWKS endpoint.
- Use \`openid\` as the minimum scope. Add \`profile\`, \`email\` as needed.

## Example Authorization Request

\`\`\`
{{authorize_endpoint}}?
  response_type=code&
  client_id={{client_id}}&
  redirect_uri={{redirect_uri}}&
  scope=openid&
  state=<RANDOM_STATE>
\`\`\`

## Example Token Exchange

\`\`\`bash
curl -X POST {{token_endpoint}} \\
  -u "{{client_id}}:\${OIDC_CLIENT_SECRET}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=<AUTH_CODE>" \\
  -d "redirect_uri={{redirect_uri}}"
\`\`\`
`;

const nativeTemplate = `# OIDC Native Client Integration

## Identity Provider

This application authenticates users via an OpenID Connect provider.

- **Issuer:** \`{{issuer}}\`
- **Discovery:** \`{{discovery_url}}\`
- **JWKS:** \`{{jwks_uri}}\`

## Client Configuration

| Field | Value |
|---|---|
| Client ID | \`{{client_id}}\` |
| Redirect URI | \`{{redirect_uri}}\` |
| Grant Type | \`authorization_code\` |
| Response Type | \`code\` |
| PKCE | Required (S256) |
| Token Auth | None (public client) |

## Endpoints

| Endpoint | URL |
|---|---|
| Authorization | \`{{authorize_endpoint}}\` |
| Token | \`{{token_endpoint}}\` |
| UserInfo | \`{{userinfo_endpoint}}\` |

## Integration Notes

- This is a **public native client** — no client secret is used.
- **PKCE is mandatory.** Generate a \`code_verifier\`, derive a SHA-256 \`code_challenge\`, and include \`code_challenge_method=S256\` in the authorize request.
- Use a custom URI scheme or \`localhost\` redirect for the callback.
- Tokens are signed JWTs. Verify signatures using keys from the JWKS endpoint.
- Use \`openid\` as the minimum scope. Add \`profile\`, \`email\` as needed.
- For mobile apps, use the system browser (ASWebAuthenticationSession / Custom Tabs) — do NOT use embedded WebViews.

## Example Authorization Request

\`\`\`
{{authorize_endpoint}}?
  response_type=code&
  client_id={{client_id}}&
  redirect_uri={{redirect_uri}}&
  scope=openid&
  code_challenge=<BASE64URL_SHA256_OF_VERIFIER>&
  code_challenge_method=S256&
  state=<RANDOM_STATE>
\`\`\`

## Example Token Exchange

\`\`\`bash
curl -X POST {{token_endpoint}} \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=<AUTH_CODE>" \\
  -d "redirect_uri={{redirect_uri}}" \\
  -d "client_id={{client_id}}" \\
  -d "code_verifier=<CODE_VERIFIER>"
\`\`\`
`;

const templates: Record<string, string> = {
  spa: spaTemplate,
  web: webTemplate,
  native: nativeTemplate
};

function renderTemplate(
  template: string,
  issuer: string,
  client: ClientSummary
): string {
  const redirectUri = client.redirect_uris[0] ?? "https://example.com/callback";
  const replacements: Record<string, string> = {
    "{{issuer}}": issuer,
    "{{client_id}}": client.client_id,
    "{{redirect_uri}}": redirectUri,
    "{{audience}}": client.access_token_audience ?? "",
    "{{authorize_endpoint}}": `${issuer}/authorize`,
    "{{token_endpoint}}": `${issuer}/token`,
    "{{jwks_uri}}": `${issuer}/jwks.json`,
    "{{userinfo_endpoint}}": `${issuer}/userinfo`,
    "{{discovery_url}}": `${issuer}/.well-known/openid-configuration`
  };
  let result = template;
  for (const [placeholder, value] of Object.entries(replacements)) {
    result = result.split(placeholder).join(value);
  }
  return result;
}

// ─── Minimal markdown-to-HTML renderer ──────────────────────────────────────

function markdownToHtml(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let inCodeBlock = false;
  let inTable = false;
  let tableRowIdx = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Code blocks
    if (line.startsWith("```")) {
      if (inCodeBlock) {
        out.push("</code></pre>");
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
        out.push('<pre style="background:var(--bg-base);border:1px solid var(--border);padding:12px 16px;overflow-x:auto;margin:8px 0;font-size:12px;line-height:1.5"><code>');
      }
      continue;
    }
    if (inCodeBlock) {
      out.push(escapeHtml(line) + "\n");
      continue;
    }

    // Table
    if (line.startsWith("|")) {
      const cells = line.split("|").slice(1, -1).map((c) => c.trim());
      // Skip separator row (|---|---|)
      if (cells.every((c) => /^-+$/.test(c))) continue;
      if (!inTable) {
        inTable = true;
        tableRowIdx = 0;
        out.push('<table style="width:100%;border-collapse:collapse;margin:8px 0;font-size:12px">');
      }
      const tag = tableRowIdx === 0 ? "th" : "td";
      const rowBg = tableRowIdx === 0 ? "var(--bg-elevated)" : tableRowIdx % 2 === 0 ? "var(--bg-surface)" : "transparent";
      out.push(`<tr style="background:${rowBg}">`);
      for (const cell of cells) {
        const style = `padding:6px 10px;border-bottom:1px solid var(--border);text-align:left;${tag === "th" ? "font-weight:600;color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:0.08em" : ""}`;
        out.push(`<${tag} style="${style}">${inlineFormat(cell)}</${tag}>`);
      }
      out.push("</tr>");
      tableRowIdx++;
      continue;
    }
    if (inTable) {
      out.push("</table>");
      inTable = false;
      tableRowIdx = 0;
    }

    // Headings
    if (line.startsWith("# ")) {
      out.push(`<h1 style="font-size:16px;font-weight:700;margin:20px 0 8px;color:var(--accent-cyan);font-family:'Space Mono',monospace;letter-spacing:0.06em">${escapeHtml(line.slice(2))}</h1>`);
      continue;
    }
    if (line.startsWith("## ")) {
      out.push(`<h2 style="font-size:13px;font-weight:600;margin:18px 0 6px;color:var(--text-primary);font-family:'Space Mono',monospace;letter-spacing:0.06em">${escapeHtml(line.slice(3))}</h2>`);
      continue;
    }

    // List items
    if (line.startsWith("- ")) {
      out.push(`<div style="padding:2px 0 2px 16px;font-size:13px;line-height:1.6;color:var(--text-secondary)">${inlineFormat(line.slice(2))}</div>`);
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      out.push("<br/>");
      continue;
    }

    // Paragraph
    out.push(`<p style="font-size:13px;line-height:1.6;margin:4px 0;color:var(--text-secondary)">${inlineFormat(line)}</p>`);
  }

  if (inTable) out.push("</table>");
  if (inCodeBlock) out.push("</code></pre>");

  return out.join("\n");
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function inlineFormat(s: string): string {
  let result = escapeHtml(s);
  // Bold
  result = result.replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>');
  // Inline code
  result = result.replace(/`([^`]+)`/g, '<code style="background:var(--bg-base);padding:1px 5px;font-size:11px;font-family:\'Space Mono\',monospace;color:var(--accent-cyan);border:1px solid var(--border)">$1</code>');
  return result;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function AgentContextModal({
  tenant,
  client,
  onClose
}: {
  tenant: TenantSummary;
  client: ClientSummary;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const issuer = tenant.issuer ?? "";
  const template = templates[client.client_profile] ?? templates.web;
  const rendered = renderTemplate(template, issuer, client);
  const html = markdownToHtml(rendered);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rendered);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      const ta = document.createElement("textarea");
      ta.value = rendered;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 50
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-bright)",
          width: "100%",
          maxWidth: "720px",
          boxShadow: "0 0 40px rgba(0,229,255,0.08)",
          position: "relative",
          overflow: "hidden"
        }}
      >
        {/* Top accent line */}
        <div
          style={{
            height: "2px",
            background:
              "linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))"
          }}
        />

        {/* Header */}
        <div
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}
        >
          <span
            className="font-display"
            style={{
              fontSize: "11px",
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              color: "var(--accent-cyan)"
            }}
          >
            AGENT CONTEXT — {client.client_name}
          </span>
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <button
              onClick={handleCopy}
              style={{
                background: "transparent",
                border: "1px solid var(--border)",
                color: copied
                  ? "var(--accent-green)"
                  : "var(--text-muted)",
                cursor: "pointer",
                fontSize: "10px",
                fontFamily: "'Space Mono', monospace",
                letterSpacing: "0.1em",
                padding: "4px 12px",
                transition: "all 0.15s"
              }}
            >
              {copied ? "COPIED" : "COPY MD"}
            </button>
            <button
              onClick={onClose}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--text-muted)",
                cursor: "pointer",
                fontSize: "18px",
                lineHeight: 1,
                padding: "2px 6px"
              }}
            >
              ×
            </button>
          </div>
        </div>

        {/* Body */}
        <div
          style={{
            padding: "20px",
            maxHeight: "calc(100vh - 140px)",
            overflowY: "auto",
            fontFamily: "'IBM Plex Sans', sans-serif"
          }}
          dangerouslySetInnerHTML={{ __html: html }}
        />
      </div>
    </div>
  );
}
