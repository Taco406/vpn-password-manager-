import { useEffect, useState } from "react";
import { Moon, Sun, Monitor, Globe, Cloud, LogIn, Download, RefreshCw, Trash2, Upload } from "lucide-react";
import type { Settings as SettingsT } from "@sentinel/shared";
import {
  bridge,
  vpnSetToken,
  vpnRealEnabled,
  syncStatus,
  syncSetConfig,
  authGoogleSignin,
  authTotpEnroll,
  authTotpVerify,
  authLogout,
  syncBackup,
  syncNow,
  syncRestore,
  syncDevices,
  syncDeviceRevoke,
  type SyncStatusInfo,
  type SyncDevice,
} from "../bridge";
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

      <ImportPasswords />

      <Card className="mb-4">
        <div className="mb-2 flex items-center justify-between text-sm font-medium">
          Telemetry <Badge tone="ok">Off · nothing to send</Badge>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          SENTINEL ships with no analytics endpoints. This switch is permanently off — there is nowhere for data to go.
        </p>
      </Card>

      <RealVpn />
      <AccountSync />
      <Updates />
    </div>
  );
}

const inputCls =
  "mono w-full rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]/50";
const btnCls =
  "rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function AccountSync() {
  const [status, setStatus] = useState<SyncStatusInfo | null>(null);
  const [serverUrl, setServerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  // Sign-in in progress: between authGoogleSignin and the TOTP verify that yields tokens.
  const [pending, setPending] = useState<{ email: string; totpRequired: boolean } | null>(null);
  const [enroll, setEnroll] = useState<{ otpauthUri: string; secret: string } | null>(null);
  const [code, setCode] = useState("");

  // Signed-in actions.
  const [backup, setBackup] = useState<{ recoveryCode: string; pdfBase64: string; version: number } | null>(null);
  const [restoreCode, setRestoreCode] = useState("");
  const [devices, setDevices] = useState<SyncDevice[]>([]);

  const refresh = async () => {
    const s = await syncStatus();
    setStatus(s);
    setServerUrl(s.serverUrl ?? "");
    setClientId(s.googleClientId ?? "");
    return s;
  };

  useEffect(() => {
    void refresh().catch(() => {});
  }, []);

  const configured = !!(status?.serverUrl && status?.googleClientId);
  const signedIn = !!status?.signedIn;

  const saveConfig = async () => {
    setBusy(true);
    setMsg("");
    try {
      await syncSetConfig(serverUrl.trim() || null, clientId.trim() || null);
      await refresh();
      setMsg("Saved.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const signin = async () => {
    setBusy(true);
    setMsg("Opening your browser — finish Google sign-in there, then come back.");
    setEnroll(null);
    setCode("");
    try {
      const p = await authGoogleSignin();
      setPending(p);
      setMsg("");
      if (p.totpRequired) {
        setEnroll(await authTotpEnroll());
      }
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const verify = async () => {
    setBusy(true);
    setMsg("");
    try {
      await authTotpVerify(code.trim());
      setPending(null);
      setEnroll(null);
      setCode("");
      await refresh();
      setMsg("Signed in.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const logout = async () => {
    setBusy(true);
    setMsg("");
    try {
      await authLogout();
      setBackup(null);
      setDevices([]);
      setPending(null);
      await refresh();
      setMsg("Signed out.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doBackup = async () => {
    setBusy(true);
    setMsg("Backing up — generating your recovery kit, this can take a few seconds.");
    try {
      const b = await syncBackup();
      setBackup(b);
      setMsg(`Backed up (server version ${b.version}).`);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doSync = async () => {
    setBusy(true);
    setMsg("Syncing…");
    try {
      const r = await syncNow();
      setMsg(`${r.pulled ? "Pulled remote changes. " : ""}Pushed. Now at version ${r.version}.`);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doRestore = async () => {
    setBusy(true);
    setMsg("Restoring from your recovery code…");
    try {
      const r = await syncRestore(restoreCode.trim());
      setRestoreCode("");
      setMsg(`Restored ${r.restored} item${r.restored === 1 ? "" : "s"}. Reopen the vault to see them.`);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const loadDevices = async () => {
    setBusy(true);
    try {
      setDevices(await syncDevices());
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const revoke = async (id: string) => {
    setBusy(true);
    try {
      await syncDeviceRevoke(id);
      await loadDevices();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Cloud size={15} /> Account &amp; Sync
        </span>
        <Badge tone={signedIn ? "ok" : "accent"}>{signedIn ? "Signed in" : "Local-only"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental and fully optional. Sign in with Google to sync your vault across devices
        end-to-end encrypted — the server only ever stores ciphertext and never sees your keys.
        Leave this untouched and SENTINEL stays entirely local. To enable it, point SENTINEL at
        your own sync server and a Google OAuth client id.
      </p>

      {/* server + client id config */}
      <div className="space-y-2">
        <div>
          <label className="mb-1 block text-xs text-[var(--text-muted)]">Sync server URL</label>
          <input
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            placeholder="https://sync.example.com"
            className={inputCls}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-[var(--text-muted)]">Google client id</label>
          <input
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="xxxxx.apps.googleusercontent.com"
            className={inputCls}
          />
        </div>
        <button onClick={saveConfig} disabled={busy} className={btnCls}>
          {busy ? "Saving…" : "Save configuration"}
        </button>
      </div>

      {/* sign-in / TOTP */}
      {!signedIn && (
        <div className="mt-4 border-t border-[var(--border-subtle)] pt-4">
          {!pending ? (
            <>
              <button
                onClick={signin}
                disabled={busy || !configured}
                className="inline-flex items-center gap-2 rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
              >
                <LogIn size={15} /> Sign in with Google
              </button>
              {!configured && (
                <p className="mt-2 text-xs text-[var(--text-muted)]">
                  Save a server URL and Google client id above to enable sign-in.
                </p>
              )}
            </>
          ) : (
            <div className="space-y-2">
              <div className="text-sm">
                Almost there{pending.email ? ` — signing in as ${pending.email}` : ""}. Enter a
                6-digit code from your authenticator to finish.
              </div>
              {enroll && (
                <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                  <div className="mb-1 text-xs text-[var(--text-muted)]">
                    First time on this account — add this secret to your authenticator app:
                  </div>
                  <div className="mono break-all text-sm text-[var(--accent)]">{enroll.secret}</div>
                </div>
              )}
              <div className="flex items-center gap-2">
                <input
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="123456"
                  className={`${inputCls} flex-1`}
                />
                <button onClick={verify} disabled={busy || code.trim().length < 6} className={btnCls}>
                  {busy ? "Verifying…" : "Verify"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* signed-in actions */}
      {signedIn && (
        <div className="mt-4 space-y-4 border-t border-[var(--border-subtle)] pt-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--text-secondary)]">
              Signed in{status?.email ? ` as ` : ""}
              {status?.email && <span className="mono text-[var(--text-primary)]">{status.email}</span>}
            </span>
            <button onClick={logout} disabled={busy} className={btnCls}>
              Sign out
            </button>
          </div>

          {/* backup */}
          <div>
            <div className="mb-1 flex items-center gap-2 text-sm font-medium">Recovery backup</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              Wraps your vault key with a one-time recovery kit and uploads the encrypted vault.
              You will need the recovery code to restore on a new device.
            </p>
            <button onClick={doBackup} disabled={busy} className={btnCls}>
              {busy ? "Working…" : "Back up now"}
            </button>
            {backup && (
              <div className="mt-3 rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-3">
                <div className="mb-1 text-xs font-semibold text-[var(--warn)]">
                  Save this recovery code now — it is shown only once and cannot be recovered.
                </div>
                <div className="mono mb-2 break-all text-sm">{backup.recoveryCode}</div>
                <a
                  href={`data:application/pdf;base64,${backup.pdfBase64}`}
                  download="sentinel-recovery-kit.pdf"
                  className="inline-flex items-center gap-2 text-xs text-[var(--accent)] hover:underline"
                >
                  <Download size={13} /> Download recovery kit (PDF)
                </a>
              </div>
            )}
          </div>

          {/* sync now */}
          <div>
            <button
              onClick={doSync}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
            >
              <RefreshCw size={15} /> Sync now
            </button>
          </div>

          {/* restore */}
          <div>
            <div className="mb-1 text-sm font-medium">Restore from another device</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              On a fresh device with an empty vault, paste the recovery code from your kit to pull
              your vault down.
            </p>
            <div className="flex items-center gap-2">
              <input
                value={restoreCode}
                onChange={(e) => setRestoreCode(e.target.value)}
                placeholder="SNTL-XXXXX-XXXXX-…"
                className={`${inputCls} flex-1`}
              />
              <button onClick={doRestore} disabled={busy || !restoreCode.trim()} className={btnCls}>
                Restore
              </button>
            </div>
          </div>

          {/* devices */}
          <div>
            <div className="mb-2 flex items-center justify-between text-sm font-medium">
              <span>Devices</span>
              <button onClick={loadDevices} disabled={busy} className={btnCls}>
                {busy ? "…" : "Refresh"}
              </button>
            </div>
            {devices.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No devices loaded yet.</p>
            ) : (
              <ul className="space-y-1">
                {devices.map((d) => (
                  <li
                    key={d.id}
                    className="flex items-center justify-between rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm"
                  >
                    <span className="flex flex-col">
                      <span>
                        {d.name}
                        {d.current && <span className="ml-2 text-xs text-[var(--accent)]">this device</span>}
                      </span>
                      <span className="text-xs text-[var(--text-muted)]">
                        {d.platform} · {d.status}
                      </span>
                    </span>
                    {!d.current && (
                      <button
                        onClick={() => revoke(d.id)}
                        disabled={busy}
                        className="inline-flex items-center gap-1 rounded-[8px] border border-[var(--danger)]/40 px-2 py-1 text-xs text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-50"
                      >
                        <Trash2 size={12} /> Revoke
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
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
        Updates <Badge tone="accent">v0.1.4</Badge>
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

function ImportPasswords() {
  const [kind, setKind] = useState<"chrome_csv" | "bitwarden_csv" | "bitwarden_json">("chrome_csv");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true);
    setStatus("");
    try {
      const content = await file.text();
      const r = await bridge.vaultImport(kind, content);
      setStatus(`Imported ${r.imported} item${r.imported === 1 ? "" : "s"}${r.skipped ? `, skipped ${r.skipped}` : ""}. Open the Vault to see them.`);
    } catch (err) {
      setStatus(`Import failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <Upload size={15} /> Import passwords
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Bring in your existing logins. Export from your current manager, then pick the format and
        choose the file. (1Password: export to a Chrome/Bitwarden CSV. Everything is encrypted
        locally on import.)
      </p>
      <div className="flex items-center gap-2">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as typeof kind)}
          className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]/50"
        >
          <option value="chrome_csv">Chrome / Edge (CSV)</option>
          <option value="bitwarden_csv">Bitwarden (CSV)</option>
          <option value="bitwarden_json">Bitwarden (JSON)</option>
        </select>
        <label className="cursor-pointer rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50">
          {busy ? "Importing…" : "Choose file…"}
          <input
            type="file"
            accept=".csv,.json,text/csv,application/json"
            onChange={onFile}
            disabled={busy}
            className="hidden"
          />
        </label>
      </div>
      {status && <p className="mt-2 text-xs text-[var(--text-muted)]">{status}</p>}
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
