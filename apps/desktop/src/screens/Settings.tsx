import { useEffect, useState } from "react";
import { Moon, Sun, Monitor } from "lucide-react";
import type { Settings as SettingsT } from "@sentinel/shared";
import { bridge } from "../bridge";
import { useApp } from "../stores/app";
import { Card, SectionTitle, Badge } from "../components/ui";

export function Settings() {
  const [s, setS] = useState<SettingsT | null>(null);
  const setTheme = useApp((a) => a.setTheme);

  useEffect(() => {
    void bridge.settingsGet().then(setS);
  }, []);

  const patch = (p: Partial<SettingsT>) => {
    if (!s) return;
    const next = { ...s, ...p };
    setS(next);
    void bridge.settingsSet(p);
  };

  if (!s) return null;

  return (
    <div className="mx-auto max-w-2xl px-8 py-8">
      <SectionTitle>Settings</SectionTitle>

      <Card className="mb-4">
        <div className="mb-3 text-sm font-medium">Appearance</div>
        <div className="flex gap-2">
          {([["dark", Moon], ["light", Sun], ["system", Monitor]] as const).map(([t, Icon]) => (
            <button
              key={t}
              onClick={() => {
                patch({ theme: t });
                setTheme(t);
              }}
              className={`flex flex-1 items-center justify-center gap-2 rounded-[10px] border py-2.5 text-sm capitalize ${
                s.theme === t ? "border-[var(--accent)]/50 bg-[var(--accent)]/10 text-[var(--accent)]" : "border-[var(--border-subtle)]"
              }`}
            >
              <Icon size={15} /> {t}
            </button>
          ))}
        </div>
        <Toggle label="Reduced motion" checked={s.reducedMotion} onChange={(v) => patch({ reducedMotion: v })} />
      </Card>

      <Card className="mb-4">
        <div className="mb-3 text-sm font-medium">Security</div>
        <Slider label="Auto-lock after" value={s.autoLockMinutes} min={1} max={60} unit="min" onChange={(v) => patch({ autoLockMinutes: v })} />
        <Slider label="Clipboard auto-clear" value={s.clipboardClearSeconds} min={5} max={120} unit="s" onChange={(v) => patch({ clipboardClearSeconds: v })} />
        <Toggle label="Kill switch on by default" checked={s.killSwitchDefault} onChange={(v) => patch({ killSwitchDefault: v })} />
      </Card>

      <Card>
        <div className="mb-2 flex items-center justify-between text-sm font-medium">
          Telemetry <Badge tone="ok">Off · nothing to send</Badge>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          SENTINEL ships with no analytics endpoints. This switch is permanently off — there is nowhere for data to go.
        </p>
      </Card>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
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

function Slider({ label, value, min, max, unit, onChange }: { label: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void }) {
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
