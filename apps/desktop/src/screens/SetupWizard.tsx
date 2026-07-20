import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Check, Lock, Globe, Puzzle } from "lucide-react";
import {
  bridge,
  lockStatus,
  lockSetPassword,
  wgStatus,
  vpnRealEnabled,
  vpnSetToken,
  autofillStatus,
  autofillPrepare,
  autofillInstall,
  openUrl,
  type WgStatusInfo,
} from "../bridge";
import { useApp } from "../stores/app";
import { Card, Button, Badge } from "../components/ui";
import { inputCls, btnCls, errMsg } from "../components/kit";

type StepKey = "welcome" | "vault" | "vpn" | "autofill" | "finish";
const ORDER: StepKey[] = ["welcome", "vault", "vpn", "autofill", "finish"];

// Live ✓/✗ status line — mirrors the Row pattern in Settings.tsx.
function StatusRow({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className={ok ? "text-[var(--ok,#16a34a)]" : "text-[var(--danger)]"}>{ok ? "✓" : "✗"}</span>
      <span className="text-[var(--text-secondary)]">{children}</span>
    </div>
  );
}

function NavFooter({ onBack, onNext, nextLabel = "Continue" }: { onBack: () => void; onNext: () => void; nextLabel?: string }) {
  return (
    <div className="mt-5 flex items-center justify-between">
      <Button variant="ghost" onClick={onBack}>Back</Button>
      <Button onClick={onNext}>{nextLabel}</Button>
    </div>
  );
}

export function SetupWizard() {
  const [step, setStep] = useState<StepKey>("welcome");
  const [finishing, setFinishing] = useState(false);
  const navigate = useNavigate();

  const idx = ORDER.indexOf(step);
  const next = () => setStep(ORDER[Math.min(idx + 1, ORDER.length - 1)]);
  const back = () => setStep(ORDER[Math.max(idx - 1, 0)]);

  // Finish AND "Skip for now" both mark onboarding complete so the gate never sends the user
  // back here — the only difference is the user reached the end vs. bailed early.
  const complete = async () => {
    setFinishing(true);
    try {
      await bridge.settingsSet({ onboardingComplete: true });
      await useApp.getState().refreshSettings();
    } catch {
      /* ignore — worst case the gate shows the wizard once more */
    }
    navigate("/vault");
  };

  return (
    <div className="flex h-full items-center justify-center p-8">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="w-[560px]">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="text-accent" size={26} />
          <span className="text-xl font-bold tracking-tight">Set up SENTINEL</span>
        </div>

        {/* Segmented stepper — copied from Onboarding.tsx */}
        <div className="mb-5 flex items-center gap-2">
          {ORDER.map((s, i) => {
            const done = idx > i;
            const active = step === s;
            return (
              <div key={s} className={`h-1 flex-1 rounded-full ${done ? "bg-[var(--accent)]" : active ? "bg-[var(--accent)]/50" : "bg-[var(--bg-inset)]"}`} />
            );
          })}
        </div>

        {step === "welcome" && (
          <Card>
            <h2 className="text-lg font-semibold">Welcome to SENTINEL</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">
              SENTINEL works out of the box. These optional steps set up the extras — you can skip any
              of them and change your mind later in Settings.
            </p>
            <Button onClick={next} className="mt-5 w-full">Get started</Button>
            <button onClick={() => void complete()} className="mt-3 block w-full text-center text-xs text-[var(--text-muted)] hover:underline">
              Skip setup
            </button>
          </Card>
        )}

        {step === "vault" && <VaultStep onBack={back} onNext={next} />}
        {step === "vpn" && <VpnStep onBack={back} onNext={next} />}
        {step === "autofill" && <AutofillStep onBack={back} onNext={next} />}

        {step === "finish" && (
          <Card className="text-center">
            <div className="mx-auto mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--ok)]/15">
              <Check className="text-[var(--ok)]" size={32} />
            </div>
            <h2 className="text-lg font-semibold">You're all set</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">
              Everything here is optional and lives in Settings — revisit it anytime.
            </p>
            <Button onClick={() => void complete()} disabled={finishing} className="mt-5 w-full">
              {finishing ? "Finishing…" : "Finish"}
            </Button>
            <button onClick={() => void complete()} className="mt-3 block w-full text-center text-xs text-[var(--text-muted)] hover:underline">
              Skip for now
            </button>
          </Card>
        )}
      </motion.div>
    </div>
  );
}

interface StepProps {
  onBack: () => void;
  onNext: () => void;
}

// Step 2 — Secure the vault with an optional master password.
function VaultStep({ onBack, onNext }: StepProps) {
  const [passwordProtected, setPasswordProtected] = useState(false);
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    try {
      const st = await lockStatus();
      setPasswordProtected(st.passwordProtected);
    } catch {
      /* ignore — mock/browser returns unlocked defaults */
    }
  };
  useEffect(() => {
    void refresh();
  }, []);

  const save = async () => {
    setBusy(true);
    setMsg("");
    try {
      await lockSetPassword(pw1);
      setPw1("");
      setPw2("");
      await refresh();
      setMsg("Master password set — you'll enter it next launch.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const mismatch = !!pw1 && !!pw2 && pw1 !== pw2;
  const canSave = pw1.length >= 4 && pw1 === pw2 && !busy;

  return (
    <Card>
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Lock size={15} /> Secure your vault
        </span>
        <Badge tone={passwordProtected ? "ok" : "neutral"}>{passwordProtected ? "Password set" : "Optional"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Add a master password to encrypt your vault (default is unlocked).
      </p>

      <div className="mb-3">
        <StatusRow ok={passwordProtected}>
          {passwordProtected ? "Vault encrypted behind a master password" : "No master password yet"}
        </StatusRow>
      </div>

      {!passwordProtected && (
        <div className="space-y-2">
          <input
            type="password"
            value={pw1}
            onChange={(e) => setPw1(e.target.value)}
            placeholder="New master password"
            className={inputCls}
          />
          <input
            type="password"
            value={pw2}
            onChange={(e) => setPw2(e.target.value)}
            placeholder="Confirm password"
            className={inputCls}
          />
          <button onClick={() => void save()} disabled={!canSave} className={btnCls}>
            {busy ? "Saving…" : "Set master password"}
          </button>
          {mismatch && <p className="text-[11px] text-[var(--danger)]">Passwords don't match.</p>}
        </div>
      )}

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
      <NavFooter onBack={onBack} onNext={onNext} />
    </Card>
  );
}

// Step 3 — Real VPN (WireGuard prerequisite + Linode token).
function VpnStep({ onBack, onNext }: StepProps) {
  const [wg, setWg] = useState<WgStatusInfo | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [token, setToken] = useState("");
  const [wgBusy, setWgBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refreshWg = async () => {
    setWgBusy(true);
    try {
      setWg(await wgStatus());
    } catch {
      /* ignore */
    }
    setWgBusy(false);
  };
  const refreshEnabled = async () => {
    try {
      setEnabled(await vpnRealEnabled());
    } catch {
      /* ignore */
    }
  };
  useEffect(() => {
    void refreshWg();
    void refreshEnabled();
  }, []);

  const save = async () => {
    setBusy(true);
    setMsg("");
    try {
      await vpnSetToken(token.trim());
      await refreshEnabled();
      setToken("");
      setMsg("Token saved — Connect will now spin up a real exit node.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const wgReady = !!wg && wg.installed && (!wg.elevationMatters || wg.elevated);

  return (
    <Card>
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Globe size={15} /> Real VPN
        </span>
        <Badge tone={enabled ? "ok" : "neutral"}>{enabled ? "On · real exit nodes" : "Optional"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        The VPN spins up throwaway servers on demand; needs WireGuard installed + a Linode token. Skip
        if you only want the password manager.
      </p>

      <div className="space-y-1.5">
        <StatusRow ok={!!wg?.installed}>
          {wg?.installed ? "WireGuard installed" : "WireGuard not detected on this PC"}
        </StatusRow>
        {wg?.elevationMatters && (
          <StatusRow ok={!!wg.elevated}>
            {wg.elevated ? "Running as administrator" : "Not elevated — relaunch SENTINEL as administrator"}
          </StatusRow>
        )}
      </div>

      <div className="mt-3 flex items-center gap-3 text-xs">
        {wg && !wg.installed && (
          <button onClick={() => void openUrl(wg.downloadUrl)} className={btnCls}>
            Download WireGuard
          </button>
        )}
        <button onClick={() => void refreshWg()} disabled={wgBusy} className="text-[var(--accent)] hover:underline disabled:opacity-50">
          {wgBusy ? "Checking…" : "Re-check"}
        </button>
      </div>

      <div className="mt-4 space-y-2">
        <StatusRow ok={enabled}>{enabled ? "Linode token saved" : "No Linode token yet"}</StatusRow>
        <div className="flex items-center gap-2">
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={enabled ? "•••••••• (token saved)" : "Linode API token"}
            className={`${inputCls} flex-1`}
          />
          <button onClick={() => void save()} disabled={busy || !token.trim()} className={btnCls}>
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
        {!wgReady && wg?.installed === false && (
          <p className="text-[11px] text-[var(--text-muted)]">
            You can save the token now and install WireGuard later — Connect needs both.
          </p>
        )}
      </div>

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
      <NavFooter onBack={onBack} onNext={onNext} />
    </Card>
  );
}

// Step 4 — Browser autofill (compact enable + load-unpacked hint).
function AutofillStep({ onBack, onNext }: StepProps) {
  const [installed, setInstalled] = useState(false);
  const [extPath, setExtPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    try {
      const s = await autofillStatus();
      setInstalled(s.installed);
    } catch {
      /* ignore */
    }
  };
  useEffect(() => {
    void refresh();
  }, []);

  const enable = async () => {
    setBusy(true);
    setMsg("");
    try {
      const path = await autofillPrepare();
      setExtPath(path);
      await autofillInstall();
      await refresh();
      setMsg("Enabled — finish by loading the folder in your browser.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <Card>
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Puzzle size={15} /> Browser autofill
        </span>
        <Badge tone={installed ? "ok" : "neutral"}>{installed ? "On · Chrome + Edge" : "Optional"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">Fill logins into Chrome/Edge.</p>

      <div className="mb-3">
        <StatusRow ok={installed}>{installed ? "Native-messaging host registered" : "Not enabled"}</StatusRow>
      </div>

      {!installed && (
        <button onClick={() => void enable()} disabled={busy} className={btnCls}>
          {busy ? "Enabling…" : "Enable"}
        </button>
      )}

      {installed && extPath && (
        <div className="mt-2 rounded-[10px] border border-[var(--border-strong)] p-3 text-xs text-[var(--text-secondary)]">
          <div className="mb-1 font-medium text-[var(--text-primary)]">Enabled ✓</div>
          <p>
            Finish in the browser: open <span className="mono">chrome://extensions</span>, turn on
            Developer mode, click <span className="mono">Load unpacked</span> and select:
          </p>
          <code className="mono mt-1 block truncate rounded bg-[var(--bg-inset)] px-2 py-1">{extPath}</code>
        </div>
      )}

      {msg && <p className="mt-2 text-xs text-[var(--text-muted)]">{msg}</p>}
      <NavFooter onBack={onBack} onNext={onNext} nextLabel="Continue" />
    </Card>
  );
}
