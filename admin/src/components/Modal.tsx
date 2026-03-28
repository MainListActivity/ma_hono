import type { ReactNode } from "react";
import { useEffect } from "react";

interface ModalProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
}

export default function Modal({ title, onClose, children }: ModalProps) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.7)',
        backdropFilter: 'blur(4px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 50
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-bright)',
        width: '100%', maxWidth: '440px',
        boxShadow: '0 0 40px rgba(0,229,255,0.08)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Top accent line */}
        <div style={{
          height: '2px',
          background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))'
        }} />

        {/* Header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between'
        }}>
          <span className="font-display" style={{
            fontSize: '11px',
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: 'var(--accent-cyan)'
          }}>
            {title}
          </span>
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none',
              color: 'var(--text-muted)', cursor: 'pointer',
              fontSize: '18px', lineHeight: 1,
              padding: '2px 6px'
            }}
          >×</button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px', maxHeight: 'calc(100vh - 140px)', overflowY: 'auto' }}>
          {children}
        </div>
      </div>
    </div>
  );
}
