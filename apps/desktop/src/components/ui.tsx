// Small UI primitives shared across screens.
import type { ReactNode } from "react";

export function Card({ children, className = "", glow = false }: { children: ReactNode; className?: string; glow?: boolean }) {
  return <div className={`surface p-5 ${glow ? "accent-glow" : ""} ${className}`}>{children}</div>;
}

export function Button({
  children,
  onClick,
  variant = "primary",
  className = "",
  type = "button",
  disabled = false,
  ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  className?: string;
  type?: "button" | "submit";
  disabled?: boolean;
  ariaLabel?: string;
}) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-[10px] px-4 py-2 text-sm font-medium transition-colors cursor-pointer select-none disabled:cursor-not-allowed disabled:opacity-50";
  const styles = {
    primary: "bg-[var(--accent)] text-[#04121a] hover:bg-[var(--accent-hover)]",
    ghost: "bg-transparent text-[var(--text-secondary)] border border-[var(--border-strong)] hover:text-[var(--text-primary)]",
    danger: "bg-transparent text-[var(--danger)] border border-[var(--danger)]/40 hover:bg-[var(--danger)]/10",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled} aria-label={ariaLabel} title={ariaLabel} className={`${base} ${styles} ${className}`}>
      {children}
    </button>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "warn" | "danger" | "ok" }) {
  const tones = {
    neutral: "bg-[var(--bg-inset)] text-[var(--text-secondary)] border-[var(--border-subtle)]",
    accent: "bg-[var(--accent)]/12 text-[var(--accent)] border-[var(--accent)]/30",
    warn: "bg-[var(--warn)]/12 text-[var(--warn)] border-[var(--warn)]/30",
    danger: "bg-[var(--danger)]/12 text-[var(--danger)] border-[var(--danger)]/30",
    ok: "bg-[var(--ok)]/12 text-[var(--ok)] border-[var(--ok)]/30",
  }[tone];
  return <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium ${tones}`}>{children}</span>;
}

export function SectionTitle({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <div className="mb-4 flex items-baseline justify-between">
      <h2 className="text-lg font-semibold tracking-tight">{children}</h2>
      {hint && <span className="text-xs text-[var(--text-muted)]">{hint}</span>}
    </div>
  );
}

export function Stat({ label, value, unit, mono = true }: { label: string; value: string; unit?: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${mono ? "mono" : ""}`}>
        {value}
        {unit && <span className="ml-1 text-sm font-normal text-[var(--text-secondary)]">{unit}</span>}
      </div>
    </div>
  );
}

export function Favicon({ domain, title }: { domain?: string; title: string }) {
  const letter = title.charAt(0).toUpperCase();
  const hue = [...title].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return (
    <div
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[8px] text-sm font-semibold"
      style={{ background: `hsl(${hue} 40% 22%)`, color: `hsl(${hue} 80% 72%)` }}
      title={domain}
    >
      {letter}
    </div>
  );
}
