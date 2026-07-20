import { useEffect, useState, type ReactElement, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Moon, Sun, Monitor, Globe, Shield, Lock, KeyRound, Smartphone, Split, X, type LucideIcon } from "lucide-react";
import type { Settings as SettingsT } from "@sentinel/shared";
import changelogRaw from "../../../../CHANGELOG.md?raw";
import {
  bridge,
  vpnSetToken,
  vpnRealEnabled,
  helloStatus,
  helloSet,
  openFolder,
  wgStatus,
  openUrl,
  vpnRepairTunnel,
  lockStatus,
  lockSetPassword,
  lockChangePassword,
  lockRemovePassword,
  lockTotpEnroll,
  lockTotpConfirm,
  lockTotpDisable,
  logTail,
  logClear,
  logDirPath,
  type WgStatusInfo,
  type AppLockStatus,
  type LockTotpEnroll,
} from "../bridge";
import { useApp } from "../stores/app";
import { Card, SectionTitle, Badge } from "../components/ui";
import { Toggle, Slider, Tabs, inputCls, btnCls } from "../components/kit";

type TabId = "general" | "security" | "vpn" | "about";

const TABS: { id: TabId; label: string; icon?: LucideIcon }[] = [
  { id: "general", label: "General", icon: Monitor },
  { id: "security", label: "Security", icon: Lock },
  { id: "vpn", label: "VPN", icon: Globe },
  { id: "about", label: "About", icon: Shield },
];

export function Settings() {
  const [s, setS] = useState<SettingsT | null>(null);
  const [tab, setTab] = useState<TabId>("general");
  const setTheme = useApp((a) => a.setTheme);
  const navigate = useNavigate();

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

      <button
        onClick={() =>
          void openFolder(
            "https://github.com/Taco406/vpn-password-manager-/blob/main/docs/setup.md",
          )
        }
        className="mb-4 text-xs text-[var(--accent)] hover:underline"
      >
        Setup &amp; required-downloads guide ↗
      </button>

      <Tabs tabs={TABS} active={tab} onChange={setTab} />

      {tab === "general" && (
        <>
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
            <div className="mb-2 flex items-center justify-between text-sm font-medium">
              Telemetry <Badge tone="ok">Off · nothing to send</Badge>
            </div>
            <p className="text-xs text-[var(--text-secondary)]">
              SENTINEL ships with no analytics endpoints. This switch is permanently off — there is nowhere for data to go.
            </p>
          </Card>

          <Card className="mb-4">
            <div className="mb-2 flex items-center justify-between text-sm font-medium">
              First-run setup
            </div>
            <p className="mb-3 text-xs text-[var(--text-secondary)]">
              Walk back through the optional setup steps — securing the vault, the real VPN, and browser autofill.
            </p>
            <button onClick={() => navigate("/setup")} className={btnCls}>
              Run setup guide again
            </button>
          </Card>
        </>
      )}

      {tab === "security" && (
        <>
          <Card className="mb-4">
            <div className="mb-3 text-sm font-medium">Security</div>
            <Slider label="Auto-lock after" value={s.autoLockMinutes} min={1} max={60} unit="min" onChange={(v) => patch({ autoLockMinutes: v })} />
            <Slider label="Clipboard auto-clear" value={s.clipboardClearSeconds} min={5} max={120} unit="s" onChange={(v) => patch({ clipboardClearSeconds: v })} />
            <Toggle label="Kill switch on by default" checked={s.killSwitchDefault} onChange={(v) => patch({ killSwitchDefault: v })} />
            <HelloRow />
          </Card>

          <AppLock />
        </>
      )}

      {tab === "vpn" && (
        <>
          <RealVpn />
          <WireGuardMonitor />
          <SplitTunnel s={s} patch={patch} />
        </>
      )}

      {tab === "about" && (
        <>
          <Updates />
          <Diagnostics />
        </>
      )}
    </div>
  );
}

function WireGuardMonitor() {
  const [st, setSt] = useState<WgStatusInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [repairMsg, setRepairMsg] = useState("");

  const refresh = async () => {
    setBusy(true);
    try {
      setSt(await wgStatus());
    } catch {
      /* ignore */
    }
    setBusy(false);
  };

  const repair = async () => {
    setRepairMsg("Removing any stuck tunnel…");
    try {
      await vpnRepairTunnel();
      setRepairMsg("Done — if internet was stuck, it should be back now.");
    } catch (e) {
      setRepairMsg(`Couldn't repair: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  // Ready = tooling present AND (elevation isn't required here OR we're elevated).
  const ready = !!st && st.installed && (!st.elevationMatters || st.elevated);
  const tone = !st ? "neutral" : !st.installed ? "danger" : ready ? "ok" : "warn";
  const label = !st ? "…" : !st.installed ? "Not installed" : ready ? "Ready" : "Needs admin";

  const Row = ({ ok, children }: { ok: boolean; children: ReactNode }) => (
    <div className="flex items-center gap-2 text-xs">
      <span className={ok ? "text-[var(--ok,#16a34a)]" : "text-[var(--danger)]"}>{ok ? "✓" : "✗"}</span>
      <span className="text-[var(--text-secondary)]">{children}</span>
    </div>
  );

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Shield size={15} /> WireGuard
        </span>
        <Badge tone={tone as "neutral" | "danger" | "ok" | "warn"}>{label}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        The real VPN needs the WireGuard tunnel driver installed, and (on Windows) SENTINEL running
        as administrator. This monitor shows both so a Connect doesn't fail after a node is created.
      </p>

      <div className="space-y-1.5">
        <Row ok={!!st?.installed}>
          {st?.installed ? (
            <>
              Installed{st.path ? <span className="mono text-[var(--text-muted)]"> · {st.path}</span> : null}
            </>
          ) : (
            "WireGuard not detected on this PC"
          )}
        </Row>
        {st?.elevationMatters && (
          <Row ok={!!st?.elevated}>
            {st?.elevated ? "Running as administrator" : "Not elevated — relaunch SENTINEL as administrator"}
          </Row>
        )}
      </div>

      <div className="mt-3 flex items-center gap-3 text-xs">
        {st && !st.installed && (
          <button
            onClick={() => void openUrl(st.downloadUrl)}
            className="rounded-[10px] border border-[var(--border-strong)] px-3 py-1.5 hover:border-[var(--accent)]/50"
          >
            Download WireGuard
          </button>
        )}
        <button onClick={() => void refresh()} disabled={busy} className="text-[var(--accent)] hover:underline">
          {busy ? "Checking…" : "Re-check"}
        </button>
        <button onClick={() => void repair()} className="text-[var(--danger)] hover:underline">
          Restore internet
        </button>
      </div>
      {repairMsg && <p className="mt-2 text-xs text-[var(--text-muted)]">{repairMsg}</p>}
      <p className="mt-2 text-[11px] text-[var(--text-muted)]">
        If a failed Connect ever leaves you without internet, click <span className="font-medium">Restore
        internet</span> above — it removes any leftover SENTINEL tunnel, clears firewall rules, and scrubs
        the routes and DNS policy WireGuard can leave behind (the app also does this automatically on
        disconnect and on launch). Last resort if it persists: uninstall WireGuard (Settings → Apps) and
        reboot, which removes any stuck adapter.
      </p>
    </Card>
  );
}

// Permissive CIDR check mirroring the backend's `looks_like_cidr`: an address part and a numeric
// prefix (≤128). Not a full validator — just enough to reject empty/garbage before persisting.
function looksLikeCidr(v: string): boolean {
  const t = v.trim();
  const slash = t.indexOf("/");
  if (slash <= 0) return false;
  const addr = t.slice(0, slash);
  const prefix = t.slice(slash + 1);
  if (!/^\d+$/.test(prefix) || Number(prefix) > 128) return false;
  return addr.includes(".") || addr.includes(":");
}

function SplitTunnel({ s, patch }: { s: SettingsT; patch: (p: Partial<SettingsT>) => void }) {
  const mode = s.tunnelMode ?? "full";
  const routes = s.splitRoutes ?? [];
  const [newRoute, setNewRoute] = useState("");
  const [hint, setHint] = useState("");

  const addRoute = (raw?: string) => {
    const v = (raw ?? newRoute).trim();
    if (!v) return;
    if (!looksLikeCidr(v)) {
      setHint(`"${v}" doesn't look like a CIDR — try something like 10.0.0.0/8.`);
      return;
    }
    if (routes.some((r) => r.toLowerCase() === v.toLowerCase())) {
      setNewRoute("");
      setHint("");
      return;
    }
    setNewRoute("");
    setHint("");
    patch({ splitRoutes: [...routes, v] });
  };

  const removeRoute = (r: string) => patch({ splitRoutes: routes.filter((x) => x !== r) });

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Split size={15} /> Split tunneling
        </span>
        <Badge tone={mode === "split" ? "accent" : "neutral"}>{mode === "split" ? "Split" : "Full tunnel"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        By default every connection routes <span className="font-medium">all</span> traffic through the
        VPN (full tunnel). Switch to <span className="font-medium">Split</span> to send only chosen
        destinations through the VPN — everything else uses your normal connection. Takes effect on your
        next Connect.
      </p>

      {/* Full / Split segmented control */}
      <div className="flex gap-2">
        {([
          ["full", "Full tunnel", "All traffic through the VPN"],
          ["split", "Split", "Only chosen routes"],
        ] as const).map(([m, label, sub]) => (
          <button
            key={m}
            onClick={() => patch({ tunnelMode: m })}
            className={`flex flex-1 flex-col items-center gap-0.5 rounded-[10px] border py-2.5 text-sm ${
              mode === m
                ? "border-[var(--accent)]/50 bg-[var(--accent)]/10 text-[var(--accent)]"
                : "border-[var(--border-subtle)]"
            }`}
          >
            <span>{label}</span>
            <span className="text-[10px] text-[var(--text-muted)]">{sub}</span>
          </button>
        ))}
      </div>

      {mode === "split" && (
        <div className="mt-3">
          <div className="mb-1 text-xs text-[var(--text-muted)]">
            Routes through the VPN — only these destinations go through the VPN; everything else uses
            your normal connection.
          </div>
          {routes.length > 0 && (
            <div className="mb-2 flex flex-wrap gap-1.5">
              {routes.map((r) => (
                <span
                  key={r}
                  className="inline-flex items-center gap-1 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2.5 py-1 text-xs"
                >
                  <span className="mono">{r}</span>
                  <button
                    onClick={() => removeRoute(r)}
                    aria-label={`Remove ${r}`}
                    className="text-[var(--text-muted)] hover:text-[var(--danger)]"
                  >
                    <X size={12} />
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <input
              value={newRoute}
              onChange={(e) => {
                setNewRoute(e.target.value);
                if (hint) setHint("");
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addRoute();
                }
              }}
              placeholder="e.g. 10.0.0.0/8"
              className={`${inputCls} flex-1`}
            />
            <button onClick={() => addRoute()} disabled={!newRoute.trim()} className={btnCls}>
              Add
            </button>
          </div>
          {hint && <p className="mt-1 text-[11px] text-[var(--danger)]">{hint}</p>}
          <p className="mt-2 text-[11px] text-[var(--text-muted)]">
            Example: <span className="mono">10.0.0.0/8</span>, <span className="mono">192.168.0.0/16</span>.
            If this list is empty (or every entry is invalid), SENTINEL safely falls back to full tunnel
            so you're never left routing nothing.
          </p>
        </div>
      )}
    </Card>
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
      // Nudge the user to secure the vault now that they're setting up the VPN — but only if
      // they haven't already added a master password.
      let tip = "";
      if (on) {
        try {
          const lk = await lockStatus();
          if (!lk.passwordProtected) {
            tip = " Tip: add a master password under App lock above to protect your vault.";
          }
        } catch {
          /* ignore */
        }
      }
      setStatus(
        on
          ? `Saved. Connect will now spin up a real Linode exit node.${tip}`
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

// Render the (bundled) CHANGELOG.md into a compact list. Handles just the subset the file
// uses: `## [ver] — date`, `### Category`, and `- bullet`; skips the title/intro and the
// reference-link definitions at the bottom.
function renderChangelog(md: string): ReactElement[] {
  const start = md.indexOf("## [");
  const body = start >= 0 ? md.slice(start) : md;
  const out: ReactElement[] = [];
  let key = 0;
  for (const raw of body.split("\n")) {
    const line = raw.trimEnd();
    if (!line.trim() || /^\[[^\]]+\]:/.test(line)) continue;
    if (line.startsWith("## ")) {
      const t = line
        .slice(3)
        .replace(/^\[(.+?)\]/, "v$1")
        .replace(/\s*—\s*/, " · ");
      out.push(
        <div key={key++} className="mt-3 mb-1 text-sm font-semibold first:mt-0">
          {t}
        </div>,
      );
    } else if (line.startsWith("### ")) {
      out.push(
        <div
          key={key++}
          className="mt-2 text-[10px] font-semibold uppercase tracking-wide text-[var(--accent)]"
        >
          {line.slice(4)}
        </div>,
      );
    } else if (line.startsWith("- ")) {
      out.push(
        <div key={key++} className="ml-1 mt-1 flex gap-1.5 text-xs text-[var(--text-secondary)]">
          <span>•</span>
          <span>{line.slice(2).replace(/\*\*/g, "")}</span>
        </div>,
      );
    } else {
      out.push(
        <div key={key++} className="ml-3.5 text-xs text-[var(--text-secondary)]">
          {line.replace(/\*\*/g, "").trim()}
        </div>,
      );
    }
  }
  return out;
}

function Diagnostics() {
  const [log, setLog] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const refresh = async () => {
    setBusy(true);
    try {
      setLog(await logTail(300));
    } catch {
      /* ignore */
    }
    setBusy(false);
  };

  useEffect(() => {
    void refresh();
  }, []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(log);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable */
    }
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        Diagnostics (error log)
        <button onClick={() => void refresh()} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
          {busy ? "…" : "Refresh"}
        </button>
      </div>
      <p className="mb-2 text-xs text-[var(--text-secondary)]">
        Errors and notable events are recorded here (no passwords or secrets). If something like a
        VPN connect fails, copy this and send it over.
      </p>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">
        {log || "No entries yet."}
      </pre>
      <div className="mt-2 flex items-center gap-3 text-xs">
        <button onClick={copy} className="text-[var(--accent)] hover:underline">
          {copied ? "Copied" : "Copy"}
        </button>
        <button onClick={async () => void openFolder(await logDirPath())} className="text-[var(--accent)] hover:underline">
          Open folder
        </button>
        <button
          onClick={async () => {
            await logClear();
            void refresh();
          }}
          className="text-[var(--danger)] hover:underline"
        >
          Clear
        </button>
      </div>
    </Card>
  );
}

function Updates() {
  const [status, setStatus] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [showNotes, setShowNotes] = useState(false);

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
        Updates <Badge tone="accent">v0.1.27</Badge>
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
        <button
          onClick={() => setShowNotes((v) => !v)}
          className="text-xs text-[var(--accent)] hover:underline"
        >
          {showNotes ? "Hide" : "What's new"}
        </button>
        {status && <span className="text-xs text-[var(--text-muted)]">{status}</span>}
      </div>
      {showNotes && (
        <div className="mt-3 max-h-72 overflow-y-auto rounded-[10px] border border-[var(--border-strong)] p-3">
          {renderChangelog(changelogRaw)}
        </div>
      )}
    </Card>
  );
}

function AppLock() {
  const [lock, setLock] = useState<AppLockStatus | null>(null);
  const [msg, setMsg] = useState("");
  // password sub-forms
  const [pwMode, setPwMode] = useState<"none" | "set" | "change" | "remove">("none");
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");
  const [oldPw, setOldPw] = useState("");
  const [pwCode, setPwCode] = useState("");
  // totp sub-flow
  const [enroll, setEnroll] = useState<LockTotpEnroll | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    try {
      setLock(await lockStatus());
    } catch {
      /* ignore */
    }
  };
  useEffect(() => {
    void refresh();
  }, []);

  const resetForms = () => {
    setPwMode("none");
    setPw1("");
    setPw2("");
    setOldPw("");
    setPwCode("");
    setEnroll(null);
    setTotpCode("");
  };

  const run = async (fn: () => Promise<void>, ok: string) => {
    setBusy(true);
    setMsg("");
    try {
      await fn();
      resetForms();
      await refresh();
      setMsg(ok);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
    setBusy(false);
  };

  const codeArg = (c: string) => (lock?.totpEnabled ? c : undefined);
  const input =
    "w-full rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]";

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Lock size={15} /> App lock
        </span>
        <Badge tone={lock?.passwordProtected ? "ok" : "neutral"}>
          {lock?.passwordProtected ? "Password set" : "Unlocked by default"}
        </Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        SENTINEL opens without a login by default. Add a <span className="font-medium">master password</span>{" "}
        to encrypt the vault behind it, and optionally require a code from your{" "}
        <span className="font-medium">authenticator app</span> (Google Authenticator, Authy…) as a second step.
      </p>

      {/* Master password */}
      <div className="rounded-[10px] border border-[var(--border-subtle)] p-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRound size={14} /> Master password
        </div>

        {!lock?.passwordProtected && pwMode === "none" && (
          <button onClick={() => setPwMode("set")} className="mt-2 text-xs text-[var(--accent)] hover:underline">
            Set a master password
          </button>
        )}
        {lock?.passwordProtected && pwMode === "none" && (
          <div className="mt-2 flex gap-3 text-xs">
            <button onClick={() => setPwMode("change")} className="text-[var(--accent)] hover:underline">Change</button>
            <button onClick={() => setPwMode("remove")} className="text-[var(--danger)] hover:underline">Remove</button>
          </div>
        )}

        {pwMode === "set" && (
          <div className="mt-2 space-y-2">
            <input type="password" value={pw1} onChange={(e) => setPw1(e.target.value)} placeholder="New master password" className={input} />
            <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} placeholder="Confirm password" className={input} />
            <div className="flex gap-2 text-xs">
              <button
                disabled={busy || pw1.length < 4 || pw1 !== pw2}
                onClick={() => void run(() => lockSetPassword(pw1), "Master password set. You'll be asked for it next launch.")}
                className="rounded-[8px] border border-[var(--border-strong)] px-3 py-1.5 hover:border-[var(--accent)]/50 disabled:opacity-50"
              >
                Save
              </button>
              <button onClick={resetForms} className="px-2 py-1.5 text-[var(--text-muted)] hover:underline">Cancel</button>
            </div>
            {pw1 && pw1 !== pw2 && <p className="text-[11px] text-[var(--danger)]">Passwords don't match.</p>}
          </div>
        )}

        {pwMode === "change" && (
          <div className="mt-2 space-y-2">
            <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} placeholder="Current password" className={input} />
            <input type="password" value={pw1} onChange={(e) => setPw1(e.target.value)} placeholder="New password" className={input} />
            {lock?.totpEnabled && (
              <input inputMode="numeric" value={pwCode} onChange={(e) => setPwCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))} placeholder="Authenticator code" className={`${input} mono tracking-widest`} />
            )}
            <div className="flex gap-2 text-xs">
              <button
                disabled={busy || pw1.length < 4 || !oldPw}
                onClick={() => void run(() => lockChangePassword(oldPw, pw1, codeArg(pwCode)), "Password changed.")}
                className="rounded-[8px] border border-[var(--border-strong)] px-3 py-1.5 hover:border-[var(--accent)]/50 disabled:opacity-50"
              >
                Change
              </button>
              <button onClick={resetForms} className="px-2 py-1.5 text-[var(--text-muted)] hover:underline">Cancel</button>
            </div>
          </div>
        )}

        {pwMode === "remove" && (
          <div className="mt-2 space-y-2">
            <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} placeholder="Current password" className={input} />
            {lock?.totpEnabled && (
              <input inputMode="numeric" value={pwCode} onChange={(e) => setPwCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))} placeholder="Authenticator code" className={`${input} mono tracking-widest`} />
            )}
            <p className="text-[11px] text-[var(--text-muted)]">Removing the password returns to unlocked-by-default (the key goes back to your OS keychain).</p>
            <div className="flex gap-2 text-xs">
              <button
                disabled={busy || !oldPw}
                onClick={() => void run(() => lockRemovePassword(oldPw, codeArg(pwCode)), "Master password removed.")}
                className="rounded-[8px] border border-[var(--danger)]/60 px-3 py-1.5 text-[var(--danger)] hover:border-[var(--danger)] disabled:opacity-50"
              >
                Remove password
              </button>
              <button onClick={resetForms} className="px-2 py-1.5 text-[var(--text-muted)] hover:underline">Cancel</button>
            </div>
          </div>
        )}
      </div>

      {/* Authenticator app */}
      <div className="mt-3 rounded-[10px] border border-[var(--border-subtle)] p-3">
        <div className="flex items-center justify-between">
          <span className="flex items-center gap-2 text-sm font-medium">
            <Smartphone size={14} /> Authenticator app
          </span>
          <Badge tone={lock?.totpEnabled ? "ok" : "neutral"}>{lock?.totpEnabled ? "On" : "Off"}</Badge>
        </div>

        {!lock?.totpEnabled && !enroll && (
          <button
            onClick={() => void run(async () => setEnroll(await lockTotpEnroll()), "")}
            disabled={busy}
            className="mt-2 text-xs text-[var(--accent)] hover:underline disabled:opacity-50"
          >
            Set up 2-step unlock
          </button>
        )}

        {enroll && (
          <div className="mt-3 flex flex-col items-center gap-2">
            <div
              className="rounded-[10px] bg-white p-2"
              // eslint-disable-next-line react/no-danger
              dangerouslySetInnerHTML={{ __html: enroll.qrSvg }}
            />
            <p className="text-[11px] text-[var(--text-muted)]">Scan in your authenticator app, or type the key:</p>
            <code className="mono select-all text-[11px] text-[var(--text-secondary)]">{enroll.secret}</code>
            <input
              inputMode="numeric"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
              placeholder="Enter the 6-digit code"
              className={`${input} mono mt-1 tracking-widest`}
            />
            <div className="flex gap-2 text-xs">
              <button
                disabled={busy || totpCode.length !== 6}
                onClick={() => void run(() => lockTotpConfirm(totpCode), "Authenticator enabled — you'll enter a code at unlock.")}
                className="rounded-[8px] border border-[var(--border-strong)] px-3 py-1.5 hover:border-[var(--accent)]/50 disabled:opacity-50"
              >
                Confirm
              </button>
              <button onClick={resetForms} className="px-2 py-1.5 text-[var(--text-muted)] hover:underline">Cancel</button>
            </div>
          </div>
        )}

        {lock?.totpEnabled && !enroll && (
          <div className="mt-2 space-y-2">
            <input
              inputMode="numeric"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
              placeholder="Current code to turn off"
              className={`${input} mono tracking-widest`}
            />
            <button
              disabled={busy || totpCode.length !== 6}
              onClick={() => void run(() => lockTotpDisable(totpCode), "Authenticator turned off.")}
              className="text-xs text-[var(--danger)] hover:underline disabled:opacity-50"
            >
              Turn off authenticator
            </button>
          </div>
        )}
      </div>

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

function HelloRow() {
  const [st, setSt] = useState<{ available: boolean; enabled: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    void helloStatus().then(setSt).catch(() => {});
  }, []);

  if (!st || !st.available) return null; // hidden unless Windows Hello is set up

  const toggle = async () => {
    setBusy(true);
    setMsg("");
    try {
      await helloSet(!st.enabled);
      setSt({ ...st, enabled: !st.enabled });
      setMsg(
        !st.enabled
          ? "On — SENTINEL will ask for Windows Hello to unlock."
          : "Off — the vault opens with your Windows sign-in.",
      );
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
    setBusy(false);
  };

  return (
    <>
      <div className="mt-3 flex items-center justify-between">
        <span className="text-sm text-[var(--text-secondary)]">Require Windows Hello to unlock</span>
        <button
          onClick={toggle}
          disabled={busy}
          className={`relative h-6 w-11 rounded-full transition-colors disabled:opacity-50 ${st.enabled ? "bg-[var(--accent)]" : "bg-[var(--bg-inset)]"}`}
        >
          <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${st.enabled ? "translate-x-[22px]" : "translate-x-0.5"}`} />
        </button>
      </div>
      {msg && <p className="mt-1 text-xs text-[var(--text-muted)]">{msg}</p>}
    </>
  );
}
