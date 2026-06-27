// Shared line icons for the auth screens. Stroke inherits from `color` unless overridden.

type IconProps = { size?: number; color?: string };

const base = (size: number, color: string) => ({
  width: size, height: size, viewBox: "0 0 24 24", fill: "none",
  stroke: color, strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const
});

export function MailIcon({ size = 16, color = "var(--text-muted)" }: IconProps) {
  return (
    <svg {...base(size, color)}>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </svg>
  );
}

export function LockIcon({ size = 16, color = "var(--text-muted)" }: IconProps) {
  return (
    <svg {...base(size, color)}>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

export function UserIcon({ size = 16, color = "var(--text-muted)" }: IconProps) {
  return (
    <svg {...base(size, color)}>
      <circle cx="12" cy="8" r="4" />
      <path d="M5.5 20a7 7 0 0 1 13 0" />
    </svg>
  );
}

export function PasskeyIcon({ size = 30, color = "var(--accent-green)" }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color}
      strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
      <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
      <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
      <path d="M2 12a10 10 0 0 1 18-6" />
      <path d="M2 16h.01" />
      <path d="M21.8 16c.2-2 .131-5.354 0-6" />
      <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
      <path d="M8.65 22c.21-.66.45-1.32.57-2" />
      <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
    </svg>
  );
}

export function PasskeyButtonIcon({ size = 18 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="#fff"
      strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
      <path d="M2 12a10 10 0 0 1 18-6" />
      <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
      <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
    </svg>
  );
}

// The ma_hono sprout brandmark.
export function BrandMark({ size = 25 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none">
      <path d="M14 53 Q32 49 50 53" stroke="#A88C68" strokeWidth="2.4" strokeLinecap="round" fill="none" />
      <path d="M25 53 L25 27" stroke="#2f7a4c" strokeWidth="3" strokeLinecap="round" />
      <path d="M25 39 C25 39 14 35 12 26 C18 26 25 32 25 39" fill="#6db87a" />
      <path d="M25 33 C25 33 35 29 37 20 C31 22 25 28 25 33" fill="#8DD49A" />
      <path d="M39 53 L39 30" stroke="#2f7a4c" strokeWidth="3" strokeLinecap="round" />
      <path d="M39 41 C39 41 50 37 52 28 C46 28 39 34 39 41" fill="#6db87a" />
      <circle cx="25" cy="54" r="3.2" fill="#cc6b3a" />
      <circle cx="39" cy="54" r="3.2" fill="#cc6b3a" />
    </svg>
  );
}

// Decorative sprout used as the floating ambient mark behind the brand panel.
export function SproutDecor({ size = 220 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none">
      <path d="M25 53 L25 27" stroke="#2f7a4c" strokeWidth="3" strokeLinecap="round" />
      <path d="M25 39 C25 39 14 35 12 26 C18 26 25 32 25 39" fill="#6db87a" />
      <path d="M25 33 C25 33 35 29 37 20 C31 22 25 28 25 33" fill="#8DD49A" />
      <path d="M39 53 L39 30" stroke="#2f7a4c" strokeWidth="3" strokeLinecap="round" />
      <path d="M39 41 C39 41 50 37 52 28 C46 28 39 34 39 41" fill="#6db87a" />
    </svg>
  );
}
