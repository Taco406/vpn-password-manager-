import { useEffect, useState } from "react";
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
} from "lucide-react";
import {
  syncServerStatus,
  syncDeploy,
  syncServerDestroy,
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
  syncDevices,
  syncDeviceRevoke,
  type SyncServerStatus,
  type SyncStatusInfo,
  type SyncDevice,
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

  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <SectionTitle hint="sync &amp; devices">Devices</SectionTitle>
      <SyncServer sync={sync} onSyncChange={refreshSync} />
      <AccountSync sync={sync} onSyncChange={refreshSync} />
    </div>
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
  const [pairCode, setPairCode] = useState<{ code: string; createdAt: string } | null>(null);
  const [joinCode, setJoinCode] = useState("");
  const [showJoin, setShowJoin] = useState(false);
  // Google sign-in: deploy-time client id + secret, plus the interactive finish-sign-in state.
  const [useGoogle, setUseGoogle] = useState(false);
  const [gClientId, setGClientId] = useState("");
  const [gSecret, setGSecret] = useState("");
  const [showGuide, setShowGuide] = useState(false);
  const [pending, setPending] = useState<{ email: string; totpRequired: boolean } | null>(null);
  const [enroll, setEnroll] = useState<{ otpauthUri: string; secret: string } | null>(null);
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
      setPairCode(null);
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

  const addDevice = async () => {
    setBusy(true);
    setMsg("");
    try {
      setPairCode(await syncPairBegin());
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

  const forget = async () => {
    if (!window.confirm("Forget this sync server on this device? Your local vault stays; the server keeps running. You can deploy or join again afterward.")) return;
    setBusy(true);
    setMsg("");
    try {
      await syncForget();
      setPairCode(null);
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
                        First device: add this secret to Google Authenticator (or any TOTP app), then enter the 6-digit code.
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
          <AddDeviceBlock busy={busy} pairCode={pairCode} onAdd={() => void addDevice()} />
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

/** "Add a device" affordance: mint a join code and show it with copy + a sensitivity warning. */
function AddDeviceBlock({ busy, pairCode, onAdd }: { busy: boolean; pairCode: { code: string; createdAt: string } | null; onAdd: () => void }) {
  return (
    <div className="!mt-2">
      {!pairCode ? (
        <button onClick={onAdd} disabled={busy} className="inline-flex items-center gap-1.5 rounded-[10px] border border-[var(--border-strong)] px-3 py-1.5 text-sm hover:border-[var(--accent)]/50 disabled:opacity-50">
          <UserPlus size={14} /> {busy ? "Working…" : "Add a device"}
        </button>
      ) : (
        <div className="space-y-2">
          <div className="rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-2 text-[11px] text-[var(--warn)]">
            This code unlocks your vault on another device — treat it like a password. It’s shown once; paste it into
            <span className="font-medium"> Devices → Join with a device code</span> on the other computer, then close this.
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
  const [enroll, setEnroll] = useState<{ otpauthUri: string; secret: string } | null>(null);
  const [code, setCode] = useState("");

  // Signed-in actions.
  const [backup, setBackup] = useState<{ recoveryCode: string; pdfBase64: string; version: number } | null>(null);
  const [restoreCode, setRestoreCode] = useState("");
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

          {/* backup */}
          <div>
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
                For a server you host yourself with a real domain. Point SENTINEL at its URL and a Google OAuth client id you
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
            </div>
          )}
        </div>
      )}

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}
