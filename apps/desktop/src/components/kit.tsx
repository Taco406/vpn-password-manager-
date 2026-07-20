// Shared UI kit: small form primitives and the tabbed-nav control used across screens.
import type { LucideIcon } from "lucide-react";

export const inputCls =
  "mono w-full rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]/50";
export const btnCls =
  "rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50";

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="mt-3 flex items-center justify-between">
      <span className="text-sm text-[var(--text-secondary)]">{label}</span>
      <button
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 rounded-full transition-colors ${checked ? "bg-[var(--accent)]" : "bg-[var(--bg-inset)]"}`}
      >
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${checked ? "translate-x-[22px]" : "translate-x-0.5"}`} />
      </button>
    </div>
  );
}

export function Slider({ label, value, min, max, unit, onChange }: { label: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void }) {
  return (
    <div className="mt-3">
      <div className="mb-1 flex items-center justify-between text-sm">
        <span className="text-[var(--text-secondary)]">{label}</span>
        <span className="mono text-[var(--text-muted)]">{value}{unit}</span>
      </div>
      <input type="range" min={min} max={max} value={value} onChange={(e) => onChange(+e.target.value)} className="w-full accent-[var(--accent)]" />
    </div>
  );
}

export function Tabs<T extends string>({ tabs, active, onChange }: {
  tabs: { id: T; label: string; icon?: LucideIcon }[];
  active: T;
  onChange: (id: T) => void;
}) {
  return (
    <div role="tablist" className="mb-6 flex flex-wrap gap-1 border-b border-[var(--border-subtle)]">
      {tabs.map(({ id, label, icon: Icon }) => {
        const on = id === active;
        return (
          <button key={id} role="tab" aria-selected={on} onClick={() => onChange(id)}
            className={`-mb-px flex items-center gap-1.5 border-b-2 px-3.5 py-2 text-sm transition-colors ${
              on ? "border-[var(--accent)] text-[var(--accent)]"
                 : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}>
            {Icon && <Icon size={14} />} {label}
          </button>
        );
      })}
    </div>
  );
}
