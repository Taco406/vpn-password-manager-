import { useEffect, useState } from "react";
import { Moon, Sun, Monitor, Globe } from "lucide-react";
import type { Settings as SettingsT } from "@sentinel/shared";
import { bridge, vpnSetToken, vpnRealEnabled } from "../bridge";
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

      <Card className="mb-4">
        <div className="mb-2 flex items-center justify-between text-sm font-medium">
          Telemetry <Badge tone="ok">Off · nothing to send</Badge>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          SENTINEL ships with no analytics endpoints. This switch is permanently off — there is nowhere for data to go.
        </p>
      </Card>

      <RealVpn />
      <Updates />
    </div>
  );
}

function RealVpn() {
  const [enabled, setEnabled] = useState(false);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  useEffect(() => {
    void vpnRealEnabled().then(setEnabled);
  }, []);

  const save = async () => {
    setBusy(true);
    setStatus("");
    try {
      await vpnSetToken(token.trim());
      const on = await vpnRealEnabled();
      setEnabled(on);
      setToken("");
      setStatus(
        on
          ? "Saved. Connect will now spin up a real Linode exit node."
          : "Token cleared. VPN is back to the built-in simulation.",
      );
    } catch (e) {
      setStatus(`Couldn't save: ${e instanceof Error ? e.message : String(e)}`);
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Globe size={15} /> Real VPN (Linode)
        </span>
        <Badge tone={enabled ? "ok" : "accent"}>{enabled ? "On · real exit nodes" : "Simulation"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental. Paste a Linode API token to make Connect spin up a real, ephemeral WireGuard
        exit node (billed ~$0.01/hr while connected, destroyed on Disconnect). Requires{" "}
        <span className="mono">WireGuard for Windows</span> installed, and SENTINEL run as
        administrator. Leave blank and Save to clear the token and return to the simulation. The
        token is stored only in Windows Credential Manager.
      </p>
      <div className="flex items-center gap-2">
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={enabled ? "•••••••• (token saved)" : "Linode API token"}
          className="mono flex-1 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]/50"
        />
        <button
          onClick={save}
          disabled={busy}
          className="rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
      {status && <p className="mt-2 text-xs text-[var(--text-muted)]">{status}</p>}
    </Card>
  );
}

function Updates() {
  const [status, setStatus] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const check = async () => {
    setBusy(true);
    const { checkForUpdate } = await import("../updater");
    const r = await checkForUpdate((st) => {
      const label: Record<string, string> = {
        idle: "Updates apply to the installed app only.",
        checking: "Checking…",
        downloading: `Downloading ${st.version ?? ""}…`,
        "up-to-date": "You're on the latest version.",
        ready: `Update ${st.version ?? ""} available.`,
        error: `Couldn't check: ${st.message ?? ""}`,
      };
      setStatus(label[st.state] ?? "");
    }, false);
    if (r.state === "ready") {
      // Found one → install and relaunch.
      await checkForUpdate(undefined, true);
    }
    setBusy(false);
  };

  return (
    <Card>
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        Updates <Badge tone="accent">v0.1.2</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        SENTINEL checks for signed updates on launch and installs them automatically. You can also check now.
      </p>
      <div className="flex items-center gap-3">
        <button
          onClick={check}
          disabled={busy}
          className="rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
        >
          {busy ? "Checking…" : "Check for updates"}
        </button>
        {status && <span className="text-xs text-[var(--text-muted)]">{status}</span>}
      </div>
    </Card>
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
