import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  Cloud,
  LogIn,
  Download,
  RefreshCw,
  Trash2,
  Copy,
  UserPlus,
  Link2,
  PlugZap,
  Shield,
  ShieldAlert,
  Ban,
} from "lucide-react";
import {
  syncServerStatus,
  syncDeploy,
  syncServerDestroy,
  syncServerUpdate,
  onSyncDeploy,
  syncStatus,
  syncSetConfig,
  syncReconnect,
  syncPairBegin,
  syncPairComplete,
  syncForget,
  syncSetGoogleSecret,
  authGoogleSignin,
  authTotpEnroll,
  authTotpVerify,
  authLogout,
  syncBackup,
  syncNow,
  syncRestore,
  syncEnablePasswordUnlock,
  syncUnlockWithPassword,
  syncDevices,
  syncDeviceRevoke,
  syncSecurityEvents,
  syncSecuritySummary,
  syncBanIp,
  syncUnbanIp,
  syncProbeServer,
  syncPasswordSignin,
  settingsSyncWrite,
  settingsSyncStatus,
  onSyncApplied,
  type ServerProbe,
  type SyncServerStatus,
  type SyncStatusInfo,
  type SyncDevice,
  type SecurityEvent,
  type SecuritySummary,
  type SettingsSyncStatusInfo,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { inputCls, btnCls, errMsg } from "../components/kit";

/** The fixed hostname a one-click (self-hosted, no-domain) server is reached at. */
const ONE_CLICK_URL = "https://sentinel-sync";

export function Devices() {
  const [sync, setSync] = useState<SyncStatusInfo | null>(null);

  const refreshSync = async () => {
    try {
      setSync(await syncStatus());
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    void refreshSync();
  }, []);

  // ONE front door: signed out, the sign-in card (server address + master password) leads and
  // the deploy/Google/join card sits below it for first-ever setup; signed in, the account card
  // leads and server management folds under Advanced.
  const settled = !!sync?.signedIn;
  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <SectionTitle hint="one account · all your devices">Account &amp; Sync</SectionTitle>
      {!settled && <SignIn onSyncChange={refreshSync} />}
      {!settled && <SyncServer sync={sync} onSyncChange={refreshSync} />}
      <AccountSync sync={sync} onSyncChange={refreshSync} />
      {settled ? (
        <AdvancedZone title="Advanced — server management &amp; attack monitor">
          <SyncServer sync={sync} onSyncChange={refreshSync} />
          <SecurityMonitor sync={sync} />
        </AdvancedZone>
      ) : (
        <SecurityMonitor sync={sync} />
      )}
    </div>
  );
}

/**
 * THE login (identical on every device): server address + master password, plus the 6-digit
 * code when 2-step sign-in is on. First contact shows the server's fingerprint to confirm
 * (trust-on-first-use); after that the certificate is pinned and everything runs over it.
 */
function SignIn({ onSyncChange }: { onSyncChange: () => void }) {
  const [address, setAddress] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [probe, setProbe] = useState<ServerProbe | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const doProbe = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const p = await syncProbeServer(address);
      setProbe(p);
      if (!p.fingerprint) setConfirmed(true); // real-CA server: TLS itself is the trust
      // Not-ready guidance renders as a persistent block below (not a transient msg), so a
      // user who already pressed "Trust this server" isn't left staring at a dead end.
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doSignin = async () => {
    if (!probe) return;
    setBusy(true);
    setMsg(needCode ? "Checking code…" : "Signing in — this takes a few seconds…");
    try {
      const r = await syncPasswordSignin({
        address,
        certPem: probe.certPem,
        password,
        code: needCode ? code : undefined,
      });
      if (r.totpRequired) {
        setNeedCode(true);
        setMsg("2-step sign-in is on for your account — enter the 6-digit code from your authenticator app.");
      } else {
        setPassword("");
        setCode("");
        setMsg(`Signed in — pulled ${r.restored} item${r.restored === 1 ? "" : "s"}. Your vault is ready.`);
        onSyncChange();
      }
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <LogIn size={15} /> Sign in to your NorthKey server
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        The same login on every device: your server’s address and your{" "}
        <span className="font-medium">master password</span>. Find the address on the computer that set the server up
        (Account &amp; Sync shows it), or scan the QR there with your phone. No server yet? Deploy one below.
      </p>
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <input
            value={address}
            onChange={(e) => {
              setAddress(e.target.value);
              setProbe(null);
              setConfirmed(false);
              setNeedCode(false);
            }}
            placeholder="Server address — e.g. 172.234.28.91"
            className={`${inputCls} flex-1`}
          />
          {!probe && (
            <button onClick={() => void doProbe()} disabled={busy || !address.trim()} className={btnCls}>
              {busy ? "Connecting…" : "Connect"}
            </button>
          )}
        </div>

        {probe && probe.fingerprint && !confirmed && (
          <div className="rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-3">
            <div className="mb-1 text-xs font-semibold">First time connecting to this server</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              Its identity code is <span className="mono font-medium text-[var(--text-primary)]">{probe.fingerprint}</span>.
              If another of your computers is signed in, it shows the same code under Account &amp; Sync — matching codes
              mean nobody is sitting between you and your server.
            </p>
            <button onClick={() => setConfirmed(true)} className={btnCls}>
              Trust this server
            </button>
          </div>
        )}

        {probe && confirmed && probe.passwordSigninReady && (
          <>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              className={`${inputCls} w-full`}
            />
            {needCode && (
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="6-digit code"
                inputMode="numeric"
                className={`${inputCls} w-full`}
              />
            )}
            <button
              onClick={() => void doSignin()}
              disabled={busy || !password || (needCode && code.trim().length < 6)}
              className="inline-flex items-center gap-2 rounded-[10px] border border-[var(--accent)]/60 bg-[var(--accent)]/10 px-3 py-2 text-sm font-medium hover:border-[var(--accent)] disabled:opacity-50"
            >
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </>
        )}

        {probe && confirmed && !probe.passwordSigninReady && (
          <div className="rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-3">
            <div className="mb-1 text-xs font-semibold">One step left — on your other computer</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              This server is yours, but master-password sign-in isn’t turned on yet. On the computer that already has your
              vault: <span className="font-medium">Account &amp; Sync → Advanced → Turn on master-password sign-in</span>{" "}
              (if that computer says the server is old, click <span className="font-medium">Update server</span> first).
              Then come back here and press Check again.
            </p>
            <button onClick={() => void doProbe()} disabled={busy} className={btnCls}>
              {busy ? "Checking…" : "Check again"}
            </button>
          </div>
        )}

        {msg && <p className="text-xs text-[var(--text-secondary)]">{msg}</p>}
      </div>
    </Card>
  );
}

/** A collapsed container for the power-user controls, so the primary flow stays three actions. */
function AdvancedZone({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4">
      <button
        onClick={() => setOpen((v) => !v)}
        className="mb-2 text-xs text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:underline"
      >
        {open ? "▾" : "▸"} {title}
      </button>
      {open && children}
    </div>
  );
}

// How each recorded event kind is labelled and coloured in the panel.
const EVENT_META: Record<string, { label: string; tone: "danger" | "warn" | "ok" | "muted" }> = {
  login_ok: { label: "Signed in", tone: "ok" },
  login_fail_bootstrap: { label: "Failed sign-in", tone: "warn" },
  google_reject: { label: "Rejected Google token", tone: "warn" },
  totp_fail: { label: "Wrong 2FA code", tone: "warn" },
  totp_lockout: { label: "2FA locked out", tone: "warn" },
  refresh_reuse: { label: "Token replay — possible theft", tone: "danger" },
  rate_limited: { label: "Rate-limited", tone: "warn" },
  banned_block: { label: "Blocked attempt", tone: "muted" },
  auto_ban: { label: "Auto-banned IP", tone: "danger" },
  enroll_fail: { label: "Bad device-enroll code", tone: "warn" },
};

const FAIL_KINDS = ["login_fail_bootstrap", "google_reject", "totp_fail", "totp_lockout", "enroll_fail"];

/** The one-shot output of "Add a device": the desktop text code + (when the server supports
 *  enrollment codes) the phone-onboarding QR. */
type PairCodeInfo = {
  code: string;
  createdAt: string;
  qrSvg?: string | null;
  qrExpiresAt?: number | null;
};

function toneClasses(tone: "danger" | "warn" | "ok" | "muted"): string {
  switch (tone) {
    case "danger":
      return "border-[var(--danger)]/40 bg-[var(--danger)]/10 text-[var(--danger)]";
    case "warn":
      return "border-[var(--warn)]/40 bg-[var(--warn)]/10 text-[var(--warn)]";
    case "ok":
      return "border-[var(--ok,var(--accent))]/40 bg-[var(--accent)]/10 text-[var(--accent)]";
    default:
      return "border-[var(--border-subtle)] bg-[var(--bg-inset)] text-[var(--text-muted)]";
  }
}

/** A single big-number tile in the 24h summary strip. */
function StatTile({ n, label, danger }: { n: number; label: string; danger?: boolean }) {
  return (
    <div className="flex-1 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-center">
      <div className={`text-lg font-semibold ${danger && n > 0 ? "text-[var(--danger)]" : "text-[var(--text-primary)]"}`}>{n}</div>
      <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
    </div>
  );
}

/**
 * Attack monitor for the sync server. Reads the server's recorded auth outcomes
 * (failed sign-ins, token replays, rate-limit trips) and lets you block/unblock IPs.
 * Only meaningful when signed in; older servers (pre-monitor) are handled gracefully.
 */
function SecurityMonitor({ sync }: { sync: SyncStatusInfo | null }) {
  const signedIn = !!sync?.signedIn;
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [blockIp, setBlockIp] = useState("");

  const load = async () => {
    setBusy(true);
    setMsg("");
    try {
      const [s, e] = await Promise.all([syncSecuritySummary(), syncSecurityEvents()]);
      setSummary(s);
      setEvents(e);
      setUnavailable(false);
    } catch (err) {
      const m = errMsg(err);
      // A server deployed before this feature has no /security-* routes yet.
      if (/HTTP 40[45]/.test(m)) setUnavailable(true);
      else setMsg(m);
    }
    setBusy(false);
  };

  useEffect(() => {
    if (signedIn) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedIn]);

  if (!signedIn) return null;

  const c = summary?.last24h ?? {};
  const failed = FAIL_KINDS.reduce((n, k) => n + (c[k] || 0), 0);
  const replays = c["refresh_reuse"] || 0;
  const signins = c["login_ok"] || 0;
  const rateLimited = c["rate_limited"] || 0;

  const block = async (ip: string, minutes?: number) => {
    const target = ip.trim();
    if (!target) return;
    setBusy(true);
    setMsg("");
    try {
      await syncBanIp(target, minutes);
      setBlockIp("");
      setMsg(`Blocked ${target}.`);
      await load();
    } catch (e) {
      setMsg(errMsg(e));
      setBusy(false);
    }
  };

  const unblock = async (ip: string) => {
    const target = ip.trim();
    if (!target) return;
    setBusy(true);
    setMsg("");
    try {
      await syncUnbanIp(target);
      setBlockIp("");
      setMsg(`Unblocked ${target}.`);
      await load();
    } catch (e) {
      setMsg(errMsg(e));
      setBusy(false);
    }
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Shield size={15} /> Attack monitor <span className="text-[11px] font-normal text-[var(--text-muted)]">(sync server)</span>
        </span>
        <div className="flex items-center gap-2">
          {summary && (
            <Badge tone={summary.autobanEnabled ? "ok" : "neutral"}>
              {summary.autobanEnabled ? "Auto-ban on" : "Detection only"}
            </Badge>
          )}
          <button onClick={() => void load()} disabled={busy} className={btnCls}>
            {busy ? "…" : "Refresh"}
          </button>
        </div>
      </div>

      {unavailable ? (
        <p className="text-xs text-[var(--text-secondary)]">
          Your sync server was deployed before the attack monitor was added. Redeploy it (Destroy, then Deploy, in the
          Sync server card above) to enable it — your vault is untouched and re-uploads after you sign back in.
        </p>
      ) : (
        <>
          <p className="mb-3 text-xs text-[var(--text-secondary)]">
            The server records every sign-in attempt so you can spot break-in attempts. Nothing sensitive is stored — no
            passwords or vault data, only the outcome, the IP, and the time. Your vault stays end-to-end encrypted regardless.
          </p>

          <div className="mb-3 flex gap-2">
            <StatTile n={failed} label="Failed 24h" danger />
            <StatTile n={replays} label="Token replays" danger />
            <StatTile n={summary?.bannedActive ?? 0} label="Blocked IPs" />
            <StatTile n={signins} label="Sign-ins" />
          </div>

          {replays > 0 && (
            <div className="mb-3 flex items-start gap-2 rounded-[10px] border border-[var(--danger)]/40 bg-[var(--danger)]/10 p-2.5 text-[11px] text-[var(--danger)]">
              <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              <span>
                A refresh token was replayed — a sign-in token may have been stolen. The affected device’s session was
                revoked automatically. Consider revoking devices above and signing in again.
              </span>
            </div>
          )}

          {!summary?.autobanEnabled && (
            <p className="mb-3 text-[11px] text-[var(--text-muted)]">
              Auto-ban is off. The monitor still records and shows attacks; to make the server block abusive IPs
              automatically, set <span className="mono">SENTINEL_AUTOBAN_THRESHOLD</span> on it (e.g. 20) and redeploy.
              {rateLimited > 0 ? ` ${rateLimited} request${rateLimited === 1 ? "" : "s"} were rate-limited in the last 24h.` : ""}
            </p>
          )}

          {/* Manual block / unblock */}
          <div className="mb-3 flex items-center gap-2">
            <input
              value={blockIp}
              onChange={(e) => setBlockIp(e.target.value)}
              placeholder="Block an IP address — e.g. 203.0.113.5"
              className={`${inputCls} flex-1`}
            />
            <button onClick={() => void block(blockIp)} disabled={busy || !blockIp.trim()} className="inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--danger)]/40 px-3 py-2 text-sm text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-50">
              <Ban size={14} /> Block
            </button>
            <button onClick={() => void unblock(blockIp)} disabled={busy || !blockIp.trim()} className={btnCls}>
              Unblock
            </button>
          </div>

          {/* Recent events */}
          <div className="mb-1 text-xs font-medium">Recent activity</div>
          {events.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">Nothing recorded yet — no sign-in attempts since the monitor started.</p>
          ) : (
            <ul className="space-y-1">
              {events.slice(0, 25).map((e) => {
                const meta = EVENT_META[e.kind] ?? { label: e.kind, tone: "muted" as const };
                return (
                  <li
                    key={e.id}
                    className="flex items-center justify-between gap-2 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-1.5 text-xs"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className={`shrink-0 rounded-[6px] border px-1.5 py-0.5 text-[10px] ${toneClasses(meta.tone)}`}>{meta.label}</span>
                      {e.ip && <span className="mono text-[var(--text-secondary)]">{e.ip}</span>}
                      {e.detail && <span className="truncate text-[var(--text-muted)]">{e.detail}</span>}
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <span className="text-[var(--text-muted)]">{new Date(e.createdAt).toLocaleString()}</span>
                      {e.ip && (
                        <button
                          onClick={() => void block(e.ip as string)}
                          disabled={busy}
                          title={`Block ${e.ip}`}
                          className="rounded-[6px] border border-[var(--danger)]/30 px-1.5 py-0.5 text-[10px] text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-50"
                        >
                          Block
                        </button>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

const SYNC_REGIONS: { id: string; label: string }[] = [
  { id: "us-east", label: "US East (Newark)" },
  { id: "us-central", label: "US Central (Dallas)" },
  { id: "us-west", label: "US West (Fremont)" },
  { id: "eu-central", label: "EU Central (Frankfurt)" },
  { id: "eu-west", label: "EU West (London)" },
  { id: "ap-south", label: "Asia (Singapore)" },
  { id: "ap-northeast", label: "Asia (Tokyo)" },
];

/** A read-only code box with a Copy button — used for device-join codes. */
function CodeBox({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — the user can still select the text */
    }
  };
  return (
    <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-2">
      <div className="mono max-h-24 overflow-auto break-all text-[11px] text-[var(--text-secondary)]">{code}</div>
      <button onClick={copy} className="mt-2 inline-flex items-center gap-1.5 text-xs text-[var(--accent)] hover:underline">
        <Copy size={12} /> {copied ? "Copied" : "Copy code"}
      </button>
    </div>
  );
}

function SyncServer({ sync, onSyncChange }: { sync: SyncStatusInfo | null; onSyncChange: () => Promise<void> }) {
  const [st, setSt] = useState<SyncServerStatus | null>(null);
  const [region, setRegion] = useState("us-east");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [msg, setMsg] = useState("");
  const [joinCode, setJoinCode] = useState("");
  const [showJoin, setShowJoin] = useState(false);
  // Google sign-in: deploy-time client id + secret, plus the interactive finish-sign-in state.
  const [useGoogle, setUseGoogle] = useState(false);
  const [gClientId, setGClientId] = useState("");
  const [gSecret, setGSecret] = useState("");
  const [showGuide, setShowGuide] = useState(false);
  const [pending, setPending] = useState<{ email: string; totpRequired: boolean } | null>(null);
  const [enroll, setEnroll] = useState<{ otpauthUri: string; secret: string; qrSvg: string } | null>(null);
  const [code, setCode] = useState("");
  // The client secret typed at sign-in time (when it wasn't saved at deploy time — Google
  // requires it for the desktop token exchange, so sign-in can't succeed without one).
  const [signinSecret, setSigninSecret] = useState("");
  // Switch an already-deployed built-in-login server over to Google sign-in (needs a redeploy).
  const [showSwitch, setShowSwitch] = useState(false);
  const [switchClientId, setSwitchClientId] = useState("");
  const [switchSecret, setSwitchSecret] = useState("");
  const [switchRegion, setSwitchRegion] = useState("us-east");
  const [switchGuide, setSwitchGuide] = useState(false);

  const signedIn = !!sync?.signedIn;
  const oneClick = sync?.serverUrl === ONE_CLICK_URL;
  // The deployed server validates real Google tokens ⇒ finish sign-in with Google, not bootstrap.
  const googleMode = !!sync?.googleClientId;

  const refresh = async () => {
    try {
      setSt(await syncServerStatus());
    } catch {
      /* ignore */
    }
  };
  useEffect(() => {
    void refresh();
    let un: (() => void) | undefined;
    void onSyncDeploy((e) => setProgress(e.detail)).then((fn) => (un = fn));
    return () => un?.();
  }, []);

  const deploy = async () => {
    setBusy(true);
    setMsg("");
    setProgress("Starting…");
    try {
      const gcid = useGoogle ? gClientId.trim() : "";
      if (useGoogle && (!gcid || !gSecret.trim())) {
        setProgress("");
        setMsg("Enter your Google client ID and client secret, or turn off “Sign in with Google”.");
        setBusy(false);
        return;
      }
      await syncDeploy(region, undefined, gcid || undefined, useGoogle ? gSecret : undefined);
      setProgress("");
      setMsg(
        gcid
          ? "Sync server is up. Click “Sign in with Google” below to finish signing this device in."
          : "Sync server is up and this device is signed in. Use “Add a device” below to connect another computer.",
      );
      await refresh();
      await onSyncChange();
    } catch (e) {
      setProgress("");
      setMsg(e instanceof Error ? e.message : String(e));
      // A deploy can fail AFTER the server record + billing exist (e.g. the first sign-in timed out
      // while the box was still installing). Refresh so the running/billed server and its
      // Destroy + Reconnect controls surface instead of leaving the card on "Not deployed".
      await refresh();
      await onSyncChange();
    }
    setBusy(false);
  };

  const destroy = async () => {
    if (!window.confirm("Destroy the sync server? This deletes the Linode and stops billing. Your local vault is untouched.")) return;
    setBusy(true);
    setMsg("");
    try {
      await syncServerDestroy();
      setMsg("Sync server destroyed. Billing stopped.");
      await refresh();
      await onSyncChange();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  // Switch a deployed built-in-login server to Google sign-in. The Google client id is baked into
  // the server at boot, so there's no in-place reconfigure — we destroy and redeploy a fresh server
  // (in the chosen region) with Google enabled. The local vault is untouched and re-uploads once
  // this device signs in; other devices will need to re-join.
  const enableGoogle = async () => {
    const gcid = switchClientId.trim();
    if (!gcid || !switchSecret.trim()) {
      setMsg("Enter your Google client ID and client secret first, or hide this to keep the built-in login.");
      return;
    }
    if (
      !window.confirm(
        "Switch to Sign in with Google?\n\nThis destroys your current sync server and redeploys a fresh one with Google enabled. Your local vault is untouched and re-uploads after you sign in. Any other devices will need to re-join.",
      )
    )
      return;
    setBusy(true);
    setProgress("Starting…");
    setMsg("Switching to Google sign-in — destroying the old server and redeploying…");
    try {
      await syncServerDestroy();
      await syncDeploy(switchRegion, undefined, gcid, switchSecret);
      setProgress("");
      setShowSwitch(false);
      setSwitchClientId("");
      setSwitchSecret("");
      setMsg("Redeployed with Google enabled. Click “Sign in with Google” below to finish.");
      await refresh();
      await onSyncChange();
    } catch (e) {
      setProgress("");
      setMsg(errMsg(e));
      await refresh();
      await onSyncChange();
    }
    setBusy(false);
  };

  const reconnect = async () => {
    setBusy(true);
    setMsg("Finishing setup — signing this device in to the server…");
    try {
      await syncReconnect();
      setMsg("Reconnected. This device is now signed in and syncing.");
      await onSyncChange();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  // Google finish-sign-in for a Google-mode server: browser PKCE → TOTP (enroll on the first
  // device, or enter the existing code on later ones) → session.
  const signinGoogle = async () => {
    // Google requires the client SECRET (not just the id) in the desktop token exchange —
    // make sure one is saved before opening the browser, or the exchange 400s at the end.
    if (!sync?.googleSecretSet && !signinSecret.trim()) {
      setMsg("Paste your Google client secret first (it's next to the Client ID in Google Cloud → Credentials).");
      return;
    }
    setBusy(true);
    setMsg("Opening your browser — finish Google sign-in there, then come back.");
    setEnroll(null);
    setCode("");
    try {
      if (signinSecret.trim()) {
        await syncSetGoogleSecret(signinSecret);
        setSigninSecret("");
        await onSyncChange();
      }
      const p = await authGoogleSignin();
      setPending(p);
      setMsg(p.totpRequired ? "Scan the QR in your authenticator, then enter the 6-digit code." : "Enter your 6-digit authenticator code.");
      if (p.totpRequired) setEnroll(await authTotpEnroll());
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const verifyGoogle = async () => {
    setBusy(true);
    setMsg("");
    try {
      await authTotpVerify(code.trim());
      setPending(null);
      setEnroll(null);
      setCode("");
      await refresh();
      await onSyncChange();
      setMsg("Signed in with Google. Your vault is syncing.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const join = async () => {
    setBusy(true);
    setMsg("Joining the sync server…");
    try {
      const r = await syncPairComplete(joinCode.trim());
      setJoinCode("");
      setShowJoin(false);
      setMsg(`Joined and pulled ${r.restored} item${r.restored === 1 ? "" : "s"} from the shared vault. Reopen the vault to see them.`);
      await refresh();
      await onSyncChange();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const updateServer = async () => {
    if (!window.confirm("Update the sync server to the latest version? It restarts its app (~30 seconds); your data is untouched.")) return;
    setBusy(true);
    setMsg("Asking the server to update itself…");
    try {
      await syncServerUpdate();
      setMsg("Update requested. The server pulls the new version and restarts — give it about a minute.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const forget = async () => {
    if (!window.confirm("Forget this sync server on this device? Your local vault stays; the server keeps running. You can deploy or join again afterward.")) return;
    setBusy(true);
    setMsg("");
    try {
      await syncForget();
      setMsg("Forgotten. This device is local-only again.");
      await refresh();
      await onSyncChange();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  // Layout branches. `configured` = this device is pointed at a one-click server (whether it
  // deployed it or joined via a code). `deployed` = this device owns the server record (can Destroy).
  const deployed = !!st?.deployed;
  const configured = oneClick || deployed;

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Cloud size={15} /> Sync server <span className="text-[11px] font-normal text-[var(--text-muted)]">(one-click)</span>
        </span>
        <Badge tone={signedIn ? "ok" : configured ? "warn" : "neutral"}>
          {deployed
            ? signedIn
              ? "Running · syncing"
              : "Running · not signed in"
            : configured
              ? signedIn
                ? "Connected"
                : "Not signed in"
              : "Not deployed"}
        </Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Spin up your <span className="font-medium">own</span> encrypted sync server on Linode with one click — it reuses your
        Real VPN token, generates its own keys, and this device signs in automatically. No Google account or domain needed.
        The vault stays end-to-end encrypted (the server only sees ciphertext). To use it on another computer, add that device
        here — no IP, cert, or login to type.
      </p>

      {/* 1. Not pointed at any server yet: deploy a new one, or join an existing one with a code. */}
      {!configured && (
        <>
          <div className="mb-2 rounded-[10px] border border-[var(--warn)]/30 bg-[var(--warn)]/10 p-2 text-[11px] text-[var(--text-secondary)]">
            Unlike the VPN, a sync server is <span className="font-medium">always on</span> and bills continuously
            (~$5/month for a Nanode) until you Destroy it. Requires a Linode token (set it under Real VPN above).
          </div>
          <div className="flex items-center gap-2">
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="flex-1 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]"
            >
              {SYNC_REGIONS.map((r) => (
                <option key={r.id} value={r.id}>{r.label}</option>
              ))}
            </select>
            <button
              onClick={() => void deploy()}
              disabled={busy}
              className="rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
            >
              {busy ? "Deploying…" : "Deploy"}
            </button>
          </div>
          {busy && progress && <p className="mt-2 text-xs text-[var(--accent)]">{progress}</p>}

          <div className="mt-3">
            <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
              <input type="checkbox" checked={useGoogle} onChange={(e) => setUseGoogle(e.target.checked)} />
              <span className="flex items-center gap-1.5"><LogIn size={13} /> Sign in with Google instead of the built-in login</span>
            </label>
            {useGoogle && (
              <div className="mt-2 space-y-2">
                <input
                  value={gClientId}
                  onChange={(e) => setGClientId(e.target.value)}
                  placeholder="Client ID — xxxxx.apps.googleusercontent.com"
                  className={`${inputCls} w-full`}
                />
                <input
                  value={gSecret}
                  onChange={(e) => setGSecret(e.target.value)}
                  placeholder="Client secret — GOCSPX-…"
                  className={`${inputCls} w-full`}
                />
                <button onClick={() => setShowGuide((v) => !v)} className="text-xs text-[var(--accent)] hover:underline">
                  {showGuide ? "Hide setup steps" : "How do I get these? (~10 min, one-time)"}
                </button>
                {showGuide && <GoogleGuideSteps />}
              </div>
            )}
          </div>

          <div className="mt-3 border-t border-[var(--border-subtle)] pt-3">
            {!showJoin ? (
              <button onClick={() => setShowJoin(true)} className="inline-flex items-center gap-1.5 text-xs text-[var(--accent)] hover:underline">
                <Link2 size={13} /> Already have a server on another computer? Join it with a device code
              </button>
            ) : (
              <div className="space-y-2">
                <div className="text-sm font-medium">Join an existing sync server</div>
                <p className="text-xs text-[var(--text-secondary)]">
                  On the computer that already has the server, open <span className="font-medium">Add a device</span> and copy its
                  code, then paste it here. This works only on a fresh install with an empty vault.
                </p>
                <textarea
                  value={joinCode}
                  onChange={(e) => setJoinCode(e.target.value)}
                  placeholder="SNTL1.…"
                  rows={3}
                  className={`${inputCls} w-full resize-y`}
                />
                <div className="flex items-center gap-2">
                  <button onClick={() => void join()} disabled={busy || !joinCode.trim()} className={btnCls}>
                    {busy ? "Joining…" : "Join server"}
                  </button>
                  <button onClick={() => { setShowJoin(false); setJoinCode(""); }} className="text-xs text-[var(--text-muted)] hover:underline">
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* 2. Pointed at a server but NOT signed in: finish/repair sign-in, or forget & start over.
             Covers a deploy whose sign-in timed out AND a joined device that later signed out. */}
      {configured && !signedIn && (
        <div className="space-y-2 text-xs text-[var(--text-secondary)]">
          {deployed && (
            <>
              <div>Server: <span className="mono">{st?.ipv4}</span>{st?.state ? ` · ${st.state}` : ""}</div>
              <div>
                Cost: <span className="font-medium">${st?.monthlyUsd?.toFixed(2)}/mo</span> (~${st?.hourlyUsd?.toFixed(3)}/hr) — billing until destroyed.
              </div>
            </>
          )}
          <div className="!mt-2 rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-2.5">
            <div className="text-[11px] text-[var(--text-secondary)]">
              This device is set up for a sync server but isn’t signed in yet
              {deployed ? " (its first sign-in likely ran before the server finished installing)" : ""}. Your vault is
              <span className="font-medium"> not syncing yet</span>. Finish setup:
            </div>
            {googleMode ? (
              <div className="mt-2 space-y-2">
                {!sync?.googleSecretSet && (
                  <div>
                    <label className="mb-1 block text-[11px] text-[var(--text-muted)]">
                      Google client secret — from the same Google Cloud → Credentials page as your Client ID
                      (Google requires it to finish sign-in; it stays on this device)
                    </label>
                    <input
                      value={signinSecret}
                      onChange={(e) => setSigninSecret(e.target.value)}
                      placeholder="GOCSPX-…"
                      className={`${inputCls} w-full`}
                    />
                  </div>
                )}
                <button onClick={() => void signinGoogle()} disabled={busy} className="inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--accent)]/50 px-3 py-1.5 text-sm text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-50">
                  <LogIn size={14} /> {busy && !pending ? "Working…" : "Sign in with Google"}
                </button>
                {pending && (
                  <div className="space-y-2">
                    {enroll && (
                      <div className="text-[11px] text-[var(--text-secondary)]">
                        First device: scan this with Google Authenticator (or any TOTP app), then enter the 6-digit code.
                        {enroll.qrSvg && (
                          <div
                            className="mt-2 w-fit rounded-[10px] bg-white p-2"
                            // eslint-disable-next-line react/no-danger
                            dangerouslySetInnerHTML={{ __html: enroll.qrSvg }}
                          />
                        )}
                        <div className="mt-1 text-[var(--text-muted)]">…or type the key instead:</div>
                        <div className="mono mt-1 break-all rounded bg-[var(--bg-inset)] p-1.5 text-[var(--text-primary)]">{enroll.secret}</div>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <input
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        inputMode="numeric"
                        placeholder="123456"
                        className={`${inputCls} w-28`}
                      />
                      <button onClick={() => void verifyGoogle()} disabled={busy || code.trim().length < 6} className={btnCls}>
                        {busy ? "Verifying…" : "Verify & finish"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <button onClick={() => void reconnect()} disabled={busy} className="mt-2 inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--accent)]/50 px-3 py-1.5 text-sm text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-50">
                <PlugZap size={14} /> {busy ? "Reconnecting…" : "Reconnect / finish setup"}
              </button>
            )}
          </div>
          <div className="flex items-center gap-4 !mt-2">
            {deployed ? (
              <button onClick={() => void destroy()} disabled={busy} className="text-[var(--danger)] hover:underline disabled:opacity-50">
                Destroy sync server (stop billing)
              </button>
            ) : (
              <button onClick={() => void forget()} disabled={busy} className="text-[var(--text-muted)] hover:underline disabled:opacity-50">
                Forget this server / start over
              </button>
            )}
          </div>
        </div>
      )}

      {/* 3. Signed in: owner sees server info + Destroy; a joined device sees a connected note; both add devices. */}
      {configured && signedIn && (
        <div className="space-y-2 text-xs text-[var(--text-secondary)]">
          {deployed ? (
            <>
              <div>Server: <span className="mono">{st?.ipv4}</span>{st?.state ? ` · ${st.state}` : ""}</div>
              <div>
                Cost: <span className="font-medium">${st?.monthlyUsd?.toFixed(2)}/mo</span> (~${st?.hourlyUsd?.toFixed(3)}/hr) — billing until destroyed.
              </div>
            </>
          ) : (
            <div>This device is connected to your sync server as an added device. The server itself is managed on the computer that deployed it.</div>
          )}
          <button onClick={() => void updateServer()} disabled={busy} className="!mt-2 block text-[var(--accent)] hover:underline disabled:opacity-50">
            Update server to the latest version
          </button>
          {deployed ? (
            <button onClick={() => void destroy()} disabled={busy} className="!mt-2 block text-[var(--danger)] hover:underline disabled:opacity-50">
              Destroy sync server (stop billing)
            </button>
          ) : (
            <button onClick={() => void forget()} disabled={busy} className="!mt-2 block text-[var(--text-muted)] hover:underline disabled:opacity-50">
              Disconnect this device from the server
            </button>
          )}
        </div>
      )}

      {/* Owner of a built-in-login server: a discoverable path to switch to Google sign-in.
          Shown whether or not this device is signed in, since the client id is fixed at the
          server's boot — switching redeploys a fresh, Google-enabled server. */}
      {deployed && !googleMode && !pending && (
        <div className="mt-3 border-t border-[var(--border-subtle)] pt-3 text-xs text-[var(--text-secondary)]">
          <div className="mb-1 flex items-center gap-1.5">
            <LogIn size={13} /> Sign-in method: <span className="font-medium">built-in login</span>
          </div>
          {!showSwitch ? (
            <button onClick={() => setShowSwitch(true)} className="text-[var(--accent)] hover:underline">
              Switch to “Sign in with Google” instead
            </button>
          ) : (
            <div className="mt-2 space-y-2 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
              <p className="text-[11px]">
                The Google client id is set when the server is built, so switching redeploys a fresh
                server with Google enabled. Your local vault is untouched and re-uploads after you sign
                in; other devices will need to re-join.
              </p>
              <div>
                <label className="mb-1 block text-[11px] text-[var(--text-muted)]">Redeploy in region</label>
                <select
                  value={switchRegion}
                  onChange={(e) => setSwitchRegion(e.target.value)}
                  className="w-full rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2 text-sm outline-none focus:border-[var(--accent)]"
                >
                  {SYNC_REGIONS.map((r) => (
                    <option key={r.id} value={r.id}>{r.label}</option>
                  ))}
                </select>
              </div>
              <input
                value={switchClientId}
                onChange={(e) => setSwitchClientId(e.target.value)}
                placeholder="Client ID — xxxxx.apps.googleusercontent.com"
                className={`${inputCls} w-full`}
              />
              <input
                value={switchSecret}
                onChange={(e) => setSwitchSecret(e.target.value)}
                placeholder="Client secret — GOCSPX-…"
                className={`${inputCls} w-full`}
              />
              <button onClick={() => setSwitchGuide((v) => !v)} className="text-[11px] text-[var(--accent)] hover:underline">
                {switchGuide ? "Hide setup steps" : "How do I get these? (~10 min, one-time)"}
              </button>
              {switchGuide && <GoogleGuideSteps />}
              <div className="flex items-center gap-3">
                <button
                  onClick={() => void enableGoogle()}
                  disabled={busy || !switchClientId.trim() || !switchSecret.trim()}
                  className={btnCls}
                >
                  {busy ? "Working…" : "Destroy & redeploy with Google"}
                </button>
                <button
                  onClick={() => {
                    setShowSwitch(false);
                    setSwitchClientId("");
                    setSwitchSecret("");
                  }}
                  className="text-[11px] text-[var(--text-muted)] hover:underline"
                >
                  Cancel
                </button>
              </div>
              {busy && progress && <p className="text-xs text-[var(--accent)]">{progress}</p>}
            </div>
          )}
        </div>
      )}

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

/** The one-time Google Cloud steps to get a Desktop-app OAuth Client ID + secret. */
function GoogleGuideSteps() {
  return (
    <ol className="list-decimal space-y-1 pl-4 text-[11px] text-[var(--text-secondary)]">
      <li>Open <span className="mono">console.cloud.google.com</span> and pick or create a project.</li>
      <li>APIs &amp; Services → OAuth consent screen → <span className="font-medium">External</span>; add your own email under Test users.</li>
      <li>APIs &amp; Services → Credentials → Create credentials → OAuth client ID → Application type <span className="font-medium">Desktop app</span>.</li>
      <li>
        Copy the <span className="font-medium">Client ID</span> (ends in <span className="mono">.apps.googleusercontent.com</span>) and
        the <span className="font-medium">Client secret</span> (starts with <span className="mono">GOCSPX-</span>) shown beside it, and
        paste both above. Google requires both to sign in from a desktop app; the secret stays on this computer.
      </li>
    </ol>
  );
}

/** "Add a device" affordance: mint a join code and show it with copy + a sensitivity warning.
 * The QR carries a ~5-minute one-time enroll code, so it shows a live countdown and flips to an
 * "expired — get a fresh one" state instead of silently going stale on screen. */
function AddDeviceBlock({
  busy,
  pairCode,
  onAdd,
}: {
  busy: boolean;
  pairCode: PairCodeInfo | null;
  onAdd: () => void;
}) {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    if (!pairCode?.qrExpiresAt) return;
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, [pairCode?.qrExpiresAt]);
  const secondsLeft = pairCode?.qrExpiresAt ? Math.max(0, pairCode.qrExpiresAt - now) : null;
  const qrExpired = secondsLeft !== null && secondsLeft <= 0;

  return (
    <div className="!mt-2">
      {!pairCode ? (
        <div>
          <div className="mb-1 text-sm font-medium text-[var(--text-primary)]">Add a device</div>
          <p className="mb-2 text-xs text-[var(--text-secondary)]">
            Put your vault on another computer or your iPhone. Your phone scans a QR; another computer pastes a code.
          </p>
          <button onClick={onAdd} disabled={busy} className="inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--border-strong)] px-3 py-1.5 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50">
            <UserPlus size={14} /> {busy ? "Working…" : "Add a device"}
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {pairCode.qrSvg && !qrExpired && (
            <div>
              <div className="mb-1 text-xs font-medium text-[var(--text-primary)]">iPhone — scan this QR</div>
              <p className="mb-2 text-[11px] text-[var(--text-secondary)]">
                In NorthKey on your phone, tap <span className="font-medium">Scan QR from desktop</span> and point it here.
                It connects the phone to your account; your master password then unlocks the vault.
              </p>
              <div
                className="w-fit rounded-[10px] bg-white p-2"
                // eslint-disable-next-line react/no-danger
                dangerouslySetInnerHTML={{ __html: pairCode.qrSvg }}
              />
              {secondsLeft !== null && (
                <p className="mt-1 text-[11px] text-[var(--text-secondary)]">
                  Good for {Math.floor(secondsLeft / 60)}:{String(secondsLeft % 60).padStart(2, "0")} more — then press New QR below.
                </p>
              )}
            </div>
          )}
          {qrExpired && (
            <div className="rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-2 text-[11px] text-[var(--warn)]">
              That QR expired — they only last about 5 minutes. Press <span className="font-medium">New QR</span> for a fresh
              one and scan again.
            </div>
          )}
          <button onClick={onAdd} disabled={busy} className="inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--border-strong)] px-3 py-1.5 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50">
            <RefreshCw size={14} /> {busy ? "Working…" : "New QR"}
          </button>
          <div className="rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-2 text-[11px] text-[var(--warn)]">
            Another computer instead? This code unlocks your vault on another device — treat it like a password. It’s shown
            once; paste it into <span className="font-medium">Account &amp; Sync → Join with a device code</span> on the
            other computer, then close this.
          </div>
          <CodeBox code={pairCode.code} />
        </div>
      )}
    </div>
  );
}

function AccountSync({ sync, onSyncChange }: { sync: SyncStatusInfo | null; onSyncChange: () => Promise<void> }) {
  const [serverUrl, setServerUrl] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Sign-in in progress: between authGoogleSignin and the TOTP verify that yields tokens.
  const [pending, setPending] = useState<{ email: string; totpRequired: boolean } | null>(null);
  const [enroll, setEnroll] = useState<{ otpauthUri: string; secret: string; qrSvg: string } | null>(null);
  const [code, setCode] = useState("");

  // Signed-in actions.
  const [backup, setBackup] = useState<{ recoveryCode: string; pdfBase64: string; version: number } | null>(null);
  const [restoreCode, setRestoreCode] = useState("");
  const [pwUnlock, setPwUnlock] = useState("");
  const [pwEnable, setPwEnable] = useState("");
  const [pairCode, setPairCode] = useState<PairCodeInfo | null>(null);
  const [devices, setDevices] = useState<SyncDevice[]>([]);

  useEffect(() => {
    setServerUrl(sync?.serverUrl ?? "");
    setClientId(sync?.googleClientId ?? "");
  }, [sync]);

  const signedIn = !!sync?.signedIn;
  const oneClick = sync?.serverUrl === ONE_CLICK_URL;
  const configured = !!(sync?.serverUrl && sync?.googleClientId);

  const saveConfig = async () => {
    setBusy(true);
    setMsg("");
    try {
      await syncSetConfig(serverUrl.trim() || null, clientId.trim() || null);
      // The secret is saved separately (keychain) and only when typed, so re-saving the
      // config never wipes a previously-stored secret.
      if (clientSecret.trim()) {
        await syncSetGoogleSecret(clientSecret);
        setClientSecret("");
      }
      await onSyncChange();
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
      await onSyncChange();
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
      await onSyncChange();
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
      await onSyncChange();
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

  const addDevice = async () => {
    setBusy(true);
    setMsg("");
    try {
      setPairCode(await syncPairBegin());
    } catch (e) {
      // Never leave a stale QR on screen next to an error — that reads as "scan me" while dead.
      setPairCode(null);
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doEnablePwUnlock = async () => {
    setBusy(true);
    setMsg("Turning on master-password sign-in…");
    try {
      const v = await syncEnablePasswordUnlock(pwEnable || undefined);
      setPwEnable("");
      setMsg(
        pwEnable
          ? `Master-password sign-in is ON (vault pushed, version ${v}). A new device now needs only your server address + master password.`
          : `Key escrowed and vault pushed (version ${v}). Enter your master password here too to enable full sign-in (address + password) on new devices.`,
      );
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doUnlockWithPassword = async () => {
    setBusy(true);
    setMsg("Unlocking from the server…");
    try {
      const r = await syncUnlockWithPassword(pwUnlock);
      setPwUnlock("");
      setMsg(
        `Unlocked — pulled ${r.restored} item${r.restored === 1 ? "" : "s"}. Reopen the vault to see them.`,
      );
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
          <Cloud size={15} /> Vault sync
        </span>
        <Badge tone={signedIn ? "ok" : "neutral"}>{signedIn ? "Signed in" : "Off · local-only"}</Badge>
      </div>

      {/* Signed in: the account actions (work for both the one-click server and a custom server). */}
      {signedIn ? (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--text-secondary)]">
              {oneClick ? "Syncing to your one-click server" : "Signed in"}
              {sync?.email ? " as " : ""}
              {sync?.email && <span className="mono text-[var(--text-primary)]">{sync.email}</span>}
              .
            </span>
            <button onClick={logout} disabled={busy} className={btnCls}>
              Sign out
            </button>
          </div>
          {(sync?.serverIp || sync?.certFingerprint) && (
            <p className="text-xs text-[var(--text-muted)]">
              To sign in on another device:
              {sync?.serverIp && (
                <>
                  {" "}server address <span className="mono text-[var(--text-secondary)]">{sync.serverIp}</span>
                </>
              )}
              {sync?.certFingerprint && (
                <>
                  {" "}· identity code <span className="mono text-[var(--text-secondary)]">{sync.certFingerprint}</span>
                </>
              )}{" "}
              + your master password.
            </p>
          )}

          {/* add a device — THE way to put your vault on another computer/phone */}
          <AddDeviceBlock busy={busy} pairCode={pairCode} onAdd={() => void addDevice()} />

          {/* shared settings status — what's shared across your devices (no secret values) */}
          <SharedSettings />

          {/* sync now — rarely needed; auto-sync runs in the background */}
          <div>
            <button
              onClick={doSync}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-[10px] border border-[var(--border-strong)] px-3 py-2 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50"
            >
              <RefreshCw size={15} /> Sync now
            </button>
            <span className="ml-2 text-xs text-[var(--text-muted)]">
              Auto-syncs in the background — you rarely need this.
            </span>
          </div>

          {/* unlock a fresh device with the master password */}
          <div>
            <div className="mb-1 text-sm font-medium">Unlock this device with your master password</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              On a <span className="font-medium">new</span> signed-in device with an empty vault: enter your account master
              password to download your key, decrypt, and pull your vault. No recovery code needed.
            </p>
            <div className="flex items-center gap-2">
              <input
                type="password"
                value={pwUnlock}
                onChange={(e) => setPwUnlock(e.target.value)}
                placeholder="Master password"
                className={`${inputCls} flex-1`}
              />
              <button onClick={doUnlockWithPassword} disabled={busy || !pwUnlock} className={btnCls}>
                Unlock
              </button>
            </div>
          </div>

          {/* Power-user paths: recovery kit + key escrow + code-based restore. */}
          <AdvancedZone title="Advanced — recovery kit &amp; restore options">
          {/* backup */}
          <div className="mb-4">
            <div className="mb-1 flex items-center gap-2 text-sm font-medium">Recovery backup</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              Wraps your vault key with a one-time recovery kit and uploads the encrypted vault. Keep the recovery code
              somewhere safe — it’s the fallback if you ever lose every signed-in device.
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
                  download="northkey-recovery-kit.pdf"
                  className="inline-flex items-center gap-2 text-xs text-[var(--accent)] hover:underline"
                >
                  <Download size={13} /> Download recovery kit (PDF)
                </a>
              </div>
            )}
          </div>

          {/* enable master-password sign-in on other devices */}
          <div>
            <div className="mb-1 text-sm font-medium">Turn on master-password sign-in</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              Escrows your master-password-wrapped key (still zero-knowledge — the server can’t read it), registers a
              one-way sign-in proof, and pushes your vault. A new device then needs only your{" "}
              <span className="font-medium">server address + master password</span> — nothing else. Enter the master
              password to confirm (it never leaves this computer).
            </p>
            <div className="flex items-center gap-2">
              <input
                type="password"
                value={pwEnable}
                onChange={(e) => setPwEnable(e.target.value)}
                placeholder="Master password"
                className={`${inputCls} flex-1`}
              />
              <button onClick={doEnablePwUnlock} disabled={busy} className={btnCls}>
                {busy ? "Working…" : "Turn on"}
              </button>
            </div>
          </div>

          {/* restore */}
          <div>
            <div className="mb-1 text-sm font-medium">Restore from your recovery code</div>
            <p className="mb-2 text-xs text-[var(--text-secondary)]">
              To bring your vault onto a <span className="font-medium">new</span> computer, the easiest way is
              <span className="font-medium"> Add a device</span> above. This box is the fallback: on a fresh device with an
              empty vault, paste the recovery code from your kit.
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
          </AdvancedZone>

          {/* devices */}
          <div>
            <div className="mb-2 flex items-center justify-between text-sm font-medium">
              <span>Signed-in devices</span>
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
      ) : oneClick ? (
        // One-click server configured but this device isn't signed in yet — point at Reconnect.
        <p className="text-xs text-[var(--text-secondary)]">
          This device has a one-click sync server configured but isn’t signed in yet. Use
          <span className="font-medium"> Reconnect / finish setup</span> in the Sync server card above to finish — you don’t
          need a Google account.
        </p>
      ) : (
        // No server at all — plain local, with the advanced bring-your-own path tucked away.
        <div className="space-y-3">
          <p className="text-xs text-[var(--text-secondary)]">
            Your vault is <span className="font-medium">local-only</span>. The simplest way to sync across devices is the
            one-click sync server above — no Google account or domain. Everything stays end-to-end encrypted either way.
          </p>
          {!showAdvanced ? (
            <button onClick={() => setShowAdvanced(true)} className="text-xs text-[var(--accent)] hover:underline">
              Advanced: use your own server + Google sign-in instead
            </button>
          ) : (
            <div className="space-y-2 border-t border-[var(--border-subtle)] pt-3">
              <p className="text-[11px] text-[var(--text-muted)]">
                For a server you host yourself with a real domain. Point NorthKey at its URL and a Google OAuth client id you
                create, then sign in with Google.
              </p>
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
              <div>
                <label className="mb-1 block text-xs text-[var(--text-muted)]">
                  Google client secret{sync?.googleSecretSet ? " (saved — retype to replace)" : ""}
                </label>
                <input
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  placeholder="GOCSPX-…"
                  className={inputCls}
                />
              </div>
              <button onClick={saveConfig} disabled={busy} className={btnCls}>
                {busy ? "Saving…" : "Save configuration"}
              </button>

              {/* sign-in / TOTP for the custom-server path */}
              <div className="mt-2 border-t border-[var(--border-subtle)] pt-3">
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
                          First time on this account — scan this with your authenticator app:
                        </div>
                        {enroll.qrSvg && (
                          <div
                            className="my-2 w-fit rounded-[10px] bg-white p-2"
                            // eslint-disable-next-line react/no-danger
                            dangerouslySetInnerHTML={{ __html: enroll.qrSvg }}
                          />
                        )}
                        <div className="mb-1 text-[11px] text-[var(--text-muted)]">…or type the key instead:</div>
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
            </div>
          )}
        </div>
      )}

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

/** Relative "N min/h/d ago" for the shared-settings last-updated line. */
function timeAgo(unix: number): string {
  if (!unix) return "";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/** The visible "Shared settings" status: which non-secret provider settings ride the encrypted
 * vault to every signed-in device (Linode / Hetzner / Google / Netdata monitors), when they were
 * last written, and a button to push the current device's settings to the others. No secret values
 * are shown or fetched — only booleans + a timestamp (see `settings_sync_status`). */
function SharedSettings() {
  const [st, setSt] = useState<SettingsSyncStatusInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = useCallback(async () => {
    try {
      setSt(await settingsSyncStatus());
    } catch {
      /* best-effort */
    }
  }, []);

  useEffect(() => {
    void refresh();
    // The background auto-sync applies pulled settings; refresh the status when it does.
    let unsub: (() => void) | undefined;
    void onSyncApplied(() => void refresh()).then((u) => (unsub = u));
    return () => unsub?.();
  }, [refresh]);

  const push = async () => {
    setBusy(true);
    setMsg("Sharing your settings with your other devices…");
    try {
      await settingsSyncWrite();
      await refresh();
      setMsg("Shared. Your other devices pick these up on their next sync.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const rows: { label: string; on: boolean; hint: string }[] = [
    { label: "Linode API token", on: !!st?.linode, hint: "VPN + server list" },
    { label: "Hetzner API token", on: !!st?.hetzner, hint: "server list + firewall" },
    { label: "Google sign-in", on: !!st?.google, hint: "OAuth client" },
    { label: "Netdata monitors", on: !!st?.netdata, hint: "per-server dashboards" },
  ];

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <div className="text-sm font-medium">Shared settings</div>
        {st?.present && st.updatedAt > 0 && (
          <span className="text-xs text-[var(--text-muted)]">updated {timeAgo(st.updatedAt)}</span>
        )}
      </div>
      <p className="mb-2 text-xs text-[var(--text-secondary)]">
        These non-secret settings ride your encrypted vault so every signed-in device — including
        your phone — sees the same servers. The token values themselves are never shown here.
      </p>
      <div className="space-y-1">
        {rows.map((r) => (
          <div
            key={r.label}
            className="flex items-center justify-between rounded-[8px] bg-[var(--bg-inset)] px-2.5 py-1.5 text-xs"
          >
            <span>
              {r.label} <span className="text-[var(--text-muted)]">· {r.hint}</span>
            </span>
            {r.on ? (
              <Badge tone="ok">synced ✓</Badge>
            ) : (
              <span className="text-[var(--text-muted)]">not set</span>
            )}
          </div>
        ))}
      </div>
      <button onClick={() => void push()} disabled={busy} className={`${btnCls} mt-2`}>
        {busy ? "Sharing…" : "Push to all my devices"}
      </button>
      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
    </div>
  );
}
