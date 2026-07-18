// A micro-toast with a countdown ring shown while a copied field is pending
// auto-clear from the clipboard.
import { useApp } from "../stores/app";
import { ClipboardCheck } from "lucide-react";

export function ClipboardCountdown() {
  const clip = useApp((s) => s.clipboard);
  if (!clip) return null;
  const total = 30000;
  const frac = Math.max(0, Math.min(1, clip.remainingMs / total));
  const secs = Math.ceil(clip.remainingMs / 1000);
  const r = 9;
  const c = 2 * Math.PI * r;

  return (
    <div className="pointer-events-none fixed bottom-6 left-1/2 z-50 -translate-x-1/2">
      <div className="surface-overlay flex items-center gap-3 px-4 py-2.5 shadow-lg">
        <ClipboardCheck size={16} className="text-accent" />
        <span className="text-sm">Copied {clip.field}</span>
        <span className="mono text-xs text-[var(--text-muted)]">clears in {secs}s</span>
        <svg width="24" height="24" viewBox="0 0 24 24" className="-rotate-90">
          <circle cx="12" cy="12" r={r} fill="none" stroke="var(--border-strong)" strokeWidth="2" />
          <circle
            cx="12"
            cy="12"
            r={r}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="2"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - frac)}
            strokeLinecap="round"
          />
        </svg>
      </div>
    </div>
  );
}
