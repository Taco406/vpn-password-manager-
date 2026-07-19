import { useEffect, useState, type ReactElement } from "react";
import { Moon, Sun, Monitor, Globe, Cloud, LogIn, Download, RefreshCw, Trash2, Upload, Puzzle, Wifi, ShieldOff, X } from "lucide-react";
import type { Settings as SettingsT } from "@sentinel/shared";
import changelogRaw from "../../../../CHANGELOG.md?raw";
import {
  bridge,
  vpnSetToken,
  vpnRealEnabled,
  helloStatus,
  helloSet,
  autofillStatus,
  autofillInstall,
  autofillUninstall,
  autofillPrepare,
  openFolder,
  netStatus,
  netSet,
  killswitchClear,
  vpnNodes,
  vpnCostSummary,
  vpnNodeAction,
  vpnNodesDestroyAll,
  vpnConnectMultihop,
  type VpnNode,
  type VpnCostSummary,
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
  type NetStatusInfo,
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
        <HelloRow />
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
      <NetGuard />
      <VpnNodes />
      <MultiHop />
      <BrowserAutofill />
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

function NetGuard() {
  const [status, setStatus] = useState<NetStatusInfo | null>(null);
  const [ssids, setSsids] = useState<string[]>([]);
  const [newSsid, setNewSsid] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    const [st, settings] = await Promise.all([netStatus(), bridge.settingsGet()]);
    setStatus(st);
    setSsids(settings.ssidAllowlist ?? []);
  };

  useEffect(() => {
    void refresh().catch(() => {});
  }, []);

  const persist = async (autoConnect: boolean, list: string[]) => {
    setBusy(true);
    setMsg("");
    try {
      await netSet(autoConnect, list);
      await refresh();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const auto = status?.autoConnect ?? false;

  const toggleAuto = () => void persist(!auto, ssids);

  const addSsid = (raw?: string) => {
    const v = (raw ?? newSsid).trim();
    setNewSsid("");
    if (!v || ssids.some((s) => s.toLowerCase() === v.toLowerCase())) return;
    const list = [...ssids, v];
    setSsids(list);
    void persist(auto, list);
  };

  const removeSsid = (s: string) => {
    const list = ssids.filter((x) => x !== s);
    setSsids(list);
    void persist(auto, list);
  };

  const clearKs = async () => {
    setBusy(true);
    setMsg("");
    try {
      await killswitchClear();
      setMsg("Kill-switch firewall rules cleared. If your connection was blocked, it's unblocked now.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const untrustedNow = !!status?.ssid && !status.trusted;

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Wifi size={15} /> Auto-connect &amp; kill switch
        </span>
        <Badge tone={auto ? "ok" : "accent"}>{auto ? "On · untrusted Wi-Fi" : "Off"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental (Windows-first) and only active in real-VPN (Linode) mode. When on, SENTINEL
        watches your Wi-Fi and automatically spins up the tunnel to your default region whenever
        you join a network that isn't on your trusted list — coffee shops, airports, hotels. It
        never auto-connects on a trusted network, and it waits a few minutes after you manually
        disconnect so it won't fight you.
      </p>

      <Toggle label="Auto-connect on untrusted Wi-Fi" checked={auto} onChange={toggleAuto} />

      {/* current network */}
      <div className="mt-3 flex items-center justify-between rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm">
        <span className="text-[var(--text-secondary)]">
          Current network:{" "}
          {status?.ssid ? (
            <span className="mono text-[var(--text-primary)]">{status.ssid}</span>
          ) : (
            <span className="text-[var(--text-muted)]">not on Wi-Fi</span>
          )}
        </span>
        {status?.ssid &&
          (status.trusted ? (
            <Badge tone="ok">Trusted</Badge>
          ) : (
            <Badge tone="accent">Untrusted</Badge>
          ))}
      </div>

      {/* trusted SSID editor */}
      <div className="mt-3">
        <div className="mb-1 text-xs text-[var(--text-muted)]">Trusted networks (no auto-connect)</div>
        {ssids.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-1.5">
            {ssids.map((s) => (
              <span
                key={s}
                className="inline-flex items-center gap-1 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2.5 py-1 text-xs"
              >
                <span className="mono">{s}</span>
                <button
                  onClick={() => removeSsid(s)}
                  disabled={busy}
                  aria-label={`Remove ${s}`}
                  className="text-[var(--text-muted)] hover:text-[var(--danger)] disabled:opacity-50"
                >
                  <X size={12} />
                </button>
              </span>
            ))}
          </div>
        )}
        <div className="flex items-center gap-2">
          <input
            value={newSsid}
            onChange={(e) => setNewSsid(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addSsid();
              }
            }}
            placeholder="Wi-Fi name (SSID)"
            className={`${inputCls} flex-1`}
          />
          <button onClick={() => addSsid()} disabled={busy || !newSsid.trim()} className={btnCls}>
            Add
          </button>
          {untrustedNow && (
            <button
              onClick={() => addSsid(status?.ssid ?? undefined)}
              disabled={busy}
              className={btnCls}
              title="Trust the network you're on right now"
            >
              Trust current
            </button>
          )}
        </div>
      </div>

      {/* kill-switch panic button */}
      <div className="mt-4 border-t border-[var(--border-subtle)] pt-4">
        <div className="mb-1 flex items-center gap-2 text-sm font-medium">
          <ShieldOff size={15} /> Kill switch
        </div>
        <p className="mb-2 text-xs text-[var(--text-secondary)]">
          When the kill switch is on (Security → &ldquo;Kill switch on by default&rdquo;), connecting
          adds Windows Firewall rules that block traffic outside the tunnel, so a dropped VPN can't
          leak. SENTINEL removes them on disconnect, on launch, and on exit. If you ever get stuck
          without internet, this button force-removes every rule right away.
        </p>
        <button onClick={clearKs} disabled={busy} className={btnCls}>
          {busy ? "Working…" : "Clear kill-switch rules"}
        </button>
      </div>

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

function BrowserAutofill() {
  const [installed, setInstalled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [extPath, setExtPath] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void autofillStatus()
      .then((s) => setInstalled(s.installed))
      .catch(() => {});
  }, []);

  // Step 1: unpack the bundled extension to a stable folder + register the host, so the only
  // thing left for the user is the browser's one-time "Load unpacked".
  const getExtension = async () => {
    setBusy(true);
    setStatus("");
    try {
      const path = await autofillPrepare();
      setExtPath(path);
      if (!installed) await autofillInstall();
      const s = await autofillStatus();
      setInstalled(s.installed);
      setStatus("Ready — now load the folder in your browser (steps below).");
    } catch (e) {
      setStatus(`Couldn't prepare: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  const disable = async () => {
    setBusy(true);
    setStatus("");
    try {
      await autofillUninstall();
      const s = await autofillStatus();
      setInstalled(s.installed);
      setStatus("Disabled. Chrome and Edge will no longer talk to SENTINEL.");
    } catch (e) {
      setStatus(`Couldn't disable: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  const copyPath = async () => {
    try {
      await navigator.clipboard.writeText(extPath);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; the path is shown for manual copy */
    }
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Puzzle size={15} /> Browser autofill
        </span>
        <Badge tone={installed ? "ok" : "accent"}>{installed ? "On · Chrome + Edge" : "Off"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental (Windows-first). Fill logins straight into Chrome and Edge. SENTINEL acts as
        the browser's native-messaging host itself — no extra program to install. A site only ever
        receives its own credentials, and nothing is available while the vault is locked.
      </p>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <button onClick={getExtension} disabled={busy} className={btnCls}>
          {busy ? "Working…" : installed ? "Re-copy extension files" : "Get the extension"}
        </button>
        {installed && (
          <button onClick={disable} disabled={busy} className={btnCls}>
            Disable
          </button>
        )}
        {status && <span className="text-xs text-[var(--text-muted)]">{status}</span>}
      </div>

      {extPath && (
        <div className="mb-3 rounded-[10px] border border-[var(--border-strong)] p-3">
          <div className="mb-2 text-xs text-[var(--text-secondary)]">
            Extension folder (you'll select this in your browser):
          </div>
          <div className="mb-2 flex items-center gap-2">
            <code className="mono flex-1 truncate rounded bg-[var(--bg-inset)] px-2 py-1 text-xs">
              {extPath}
            </code>
            <button onClick={copyPath} className="text-xs text-[var(--accent)] hover:underline">
              {copied ? "Copied" : "Copy path"}
            </button>
            <button
              onClick={() => void openFolder(extPath)}
              className="text-xs text-[var(--accent)] hover:underline"
            >
              Open folder
            </button>
          </div>
          <ol className="list-decimal space-y-1 pl-5 text-xs text-[var(--text-secondary)]">
            <li>
              Open <span className="mono">chrome://extensions</span> (or{" "}
              <span className="mono">edge://extensions</span>).
            </li>
            <li>
              Turn on <span className="mono">Developer mode</span> (top-right).
            </li>
            <li>
              Click <span className="mono">Load unpacked</span> and select the folder above.
            </li>
          </ol>
        </div>
      )}
    </Card>
  );
}

function MultiHop() {
  const [enabled, setEnabled] = useState(false);
  const [regions, setRegions] = useState<{ id: string; label: string }[]>([]);
  const [hops, setHops] = useState<string[]>(["", ""]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const on = await vpnRealEnabled();
        setEnabled(on);
        if (on) {
          const rs = await bridge.vpnRegions();
          const opts = rs.map((r) => ({ id: r.id, label: r.label ?? r.id }));
          setRegions(opts);
          if (opts.length >= 2) setHops([opts[0].id, opts[1].id]);
        }
      } catch {
        /* ignore */
      }
    })();
  }, []);

  if (!enabled) return null;

  const setHop = (i: number, v: string) => setHops((h) => h.map((x, j) => (j === i ? v : x)));
  const addHop = () => setHops((h) => (h.length < 3 ? [...h, regions[0]?.id ?? ""] : h));
  const removeHop = () => setHops((h) => (h.length > 2 ? h.slice(0, -1) : h));

  const connect = async () => {
    if (hops.some((h) => !h)) {
      setMsg("Pick a region for each hop.");
      return;
    }
    setBusy(true);
    setMsg("Building the chain… this provisions one node per hop and can take a minute.");
    try {
      await vpnConnectMultihop(hops);
      setMsg("Connected through the chain. Disconnect on the VPN screen destroys every hop.");
    } catch (e) {
      setMsg(`Couldn't connect: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Globe size={15} /> Multi-hop (bounce)
        </span>
        <Badge tone="warn">experimental</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Route your traffic through 2–3 exit nodes in a row (entry → exit). More privacy, but{" "}
        <span className="font-medium">cost is N× a single node</span> and latency adds up. One local
        tunnel; the hops chain server-side. Windows-first and experimental — first real use is a test.
      </p>
      <div className="space-y-2">
        {hops.map((h, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="w-14 text-[var(--text-muted)]">
              {i === 0 ? "Entry" : i === hops.length - 1 ? "Exit" : `Hop ${i + 1}`}
            </span>
            <select
              value={h}
              onChange={(e) => setHop(i, e.target.value)}
              className="flex-1 rounded-[10px] border border-[var(--border-subtle)] bg-transparent px-2 py-1.5"
            >
              {regions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button onClick={connect} disabled={busy} className="rounded-[10px] bg-[var(--accent)] px-3 py-2 text-sm text-black disabled:opacity-50">
          {busy ? "Connecting…" : `Connect · ${hops.length} hops`}
        </button>
        {hops.length < 3 && (
          <button onClick={addHop} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
            + hop
          </button>
        )}
        {hops.length > 2 && (
          <button onClick={removeHop} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
            − hop
          </button>
        )}
        {msg && <span className="text-xs text-[var(--text-muted)]">{msg}</span>}
      </div>
    </Card>
  );
}

function VpnNodes() {
  const [enabled, setEnabled] = useState(false);
  const [nodes, setNodes] = useState<VpnNode[]>([]);
  const [cost, setCost] = useState<VpnCostSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    setBusy(true);
    setMsg("");
    try {
      const on = await vpnRealEnabled();
      setEnabled(on);
      if (on) {
        const [n, c] = await Promise.all([vpnNodes(), vpnCostSummary()]);
        setNodes(n);
        setCost(c);
      }
    } catch (e) {
      setMsg(`Couldn't load nodes: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  useEffect(() => {
    void refresh();
  }, []);

  const act = async (id: string, action: "start" | "stop" | "reboot" | "delete") => {
    if (action === "delete" && !confirm("Destroy this node? This permanently deletes it (and stops its billing).")) return;
    setBusy(true);
    setMsg("");
    try {
      await vpnNodeAction(id, action);
      await refresh();
    } catch (e) {
      setMsg(`Action failed: ${errMsg(e)}`);
      setBusy(false);
    }
  };

  const destroyAll = async () => {
    if (!confirm("Destroy ALL exit nodes? This stops all billing and disconnects you.")) return;
    setBusy(true);
    setMsg("");
    try {
      const n = await vpnNodesDestroyAll();
      setMsg(`Destroyed ${n} node${n === 1 ? "" : "s"}.`);
      await refresh();
    } catch (e) {
      setMsg(`Couldn't destroy all: ${errMsg(e)}`);
      setBusy(false);
    }
  };

  if (!enabled) return null; // only meaningful in real-VPN (Linode) mode

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Cloud size={15} /> VPN exit nodes
        </span>
        <button onClick={() => void refresh()} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
          {busy ? "…" : "Refresh"}
        </button>
      </div>

      {cost && cost.nodeCount > 0 && (
        <div className="mb-3 rounded-[10px] border border-[var(--border-strong)] p-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[var(--text-secondary)]">
              {cost.nodeCount} node{cost.nodeCount === 1 ? "" : "s"} · {cost.running} running · {cost.stopped} stopped
            </span>
            <span className="font-medium">~${cost.hourlyUsd.toFixed(4)}/hr</span>
          </div>
          <p className="mt-1 text-[var(--text-muted)]">
            A stopped node still bills — only <span className="font-medium">Destroy</span> stops the meter.
          </p>
        </div>
      )}

      {nodes.length === 0 ? (
        <p className="text-xs text-[var(--text-secondary)]">
          No exit nodes right now. Connecting on the VPN screen creates one; use “Disconnect &amp; keep” to power one
          off without destroying it.
        </p>
      ) : (
        <div className="space-y-2">
          {nodes.map((n) => (
            <div key={n.id} className="flex flex-wrap items-center gap-2 rounded-[10px] border border-[var(--border-subtle)] p-2 text-xs">
              <span className="mono">{n.region}</span>
              <Badge tone={n.state === "running" ? "ok" : n.state === "stopped" ? "neutral" : "accent"}>{n.state}</Badge>
              {n.current && <Badge tone="accent">connected</Badge>}
              {n.kept && <Badge tone="neutral">kept</Badge>}
              <span className="text-[var(--text-muted)]">~${n.hourlyUsd.toFixed(4)}/hr</span>
              <span className="ml-auto flex gap-2">
                {n.state === "stopped" ? (
                  <button onClick={() => void act(n.id, "start")} disabled={busy} className="text-[var(--accent)] hover:underline">Start</button>
                ) : (
                  <button onClick={() => void act(n.id, "stop")} disabled={busy} className="text-[var(--accent)] hover:underline">Stop</button>
                )}
                <button onClick={() => void act(n.id, "reboot")} disabled={busy} className="text-[var(--accent)] hover:underline">Reboot</button>
                <button onClick={() => void act(n.id, "delete")} disabled={busy} className="text-[var(--danger)] hover:underline">Destroy</button>
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="mt-3 flex items-center gap-3">
        {nodes.length > 0 && (
          <button onClick={() => void destroyAll()} disabled={busy} className={btnCls}>
            Destroy all nodes
          </button>
        )}
        {msg && <span className="text-xs text-[var(--text-muted)]">{msg}</span>}
      </div>
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
        Updates <Badge tone="accent">v0.1.13</Badge>
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
