import type { ReactNode } from "react";
import { BrandMark, SproutDecor } from "./icons";

// ─── Shared field/button styles ───────────────────────────────────────────────

export const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "12px 14px 12px 40px",
  fontSize: "14px",
  color: "var(--text-primary)",
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  borderRadius: "10px",
  outline: "none",
  boxSizing: "border-box",
  transition: "border-color .15s, box-shadow .15s, background .15s"
};

export const fieldWrapStyle: React.CSSProperties = {
  position: "relative"
};

export const iconSpanStyle: React.CSSProperties = {
  position: "absolute",
  left: "13px",
  top: "50%",
  transform: "translateY(-50%)",
  display: "grid",
  placeItems: "center",
  pointerEvents: "none"
};

export const primaryButtonStyle = (disabled: boolean): React.CSSProperties => ({
  width: "100%",
  padding: "13px",
  border: 0,
  borderRadius: "10px",
  background: disabled ? "var(--text-dim)" : "var(--accent-green)",
  color: "#fff",
  fontSize: "14px",
  fontWeight: 600,
  cursor: disabled ? "not-allowed" : "pointer",
  transition: "background .15s, transform .05s",
  boxShadow: disabled ? "none" : "0 10px 22px -10px rgba(47,122,76,.6)"
});

export function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <label style={{ display: "block", fontSize: "12px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "7px" }}>
      {children}
    </label>
  );
}

// ─── Layout shell: centered split card on the warm ambient page ───────────────

export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="dot-grid" style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "48px 24px",
      fontFamily: "var(--font-sans)"
    }}>
      <div style={{
        display: "flex",
        width: "100%",
        maxWidth: "880px",
        minHeight: "560px",
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: "20px",
        overflow: "hidden",
        boxShadow: "0 34px 80px -34px rgba(34,30,23,.30)"
      }}>
        {children}
      </div>
    </div>
  );
}

// ─── Brand panel (left side) ──────────────────────────────────────────────────

export function BrandPanel({
  heading,
  description,
  footer
}: {
  heading: ReactNode;
  description: ReactNode;
  footer: ReactNode;
}) {
  return (
    <div className="auth-brand-panel" style={{
      position: "relative",
      width: "330px",
      flexShrink: 0,
      padding: "38px 34px",
      display: "flex",
      flexDirection: "column",
      justifyContent: "space-between",
      background: "var(--brand-gradient)",
      borderRight: "1px solid var(--border)"
    }}>
      <div style={{ position: "absolute", right: "-40px", top: "120px", opacity: 0.1, animation: "floaty 7s ease-in-out infinite" }}>
        <SproutDecor size={220} />
      </div>

      <div style={{ position: "relative", display: "flex", alignItems: "center", gap: "11px" }}>
        <span style={{ display: "grid", placeItems: "center", width: "40px", height: "40px", borderRadius: "11px", background: "#fff", boxShadow: "0 2px 8px rgba(34,30,23,.10)" }}>
          <BrandMark size={25} />
        </span>
        <span style={{ display: "flex", flexDirection: "column", lineHeight: 1 }}>
          <span className="font-serif" style={{ fontWeight: 600, fontSize: "21px", color: "var(--text-primary)", letterSpacing: "0.3px" }}>ma_hono</span>
          <span style={{ marginTop: "5px", fontSize: "9.5px", letterSpacing: "0.28em", textTransform: "uppercase", color: "var(--text-muted)" }}>Identity</span>
        </span>
      </div>

      <div style={{ position: "relative" }}>
        <h2 className="font-serif" style={{ margin: "0 0 12px", fontWeight: 600, fontSize: "27px", lineHeight: 1.28, color: "var(--text-primary)" }}>
          {heading}
        </h2>
        <p style={{ margin: 0, fontSize: "13px", lineHeight: 1.65, color: "var(--text-secondary)", maxWidth: "230px" }}>
          {description}
        </p>
      </div>

      <div style={{ position: "relative" }}>{footer}</div>
    </div>
  );
}
