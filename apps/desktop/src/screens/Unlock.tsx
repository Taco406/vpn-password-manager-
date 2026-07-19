import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Shield, Fingerprint, Smartphone, KeyRound, Loader2, Lock } from "lucide-react";
import type { KeyringStatus } from "@sentinel/shared";
import { bridge, lockStatus, lockUnlockPassword, type AppLockStatus } from "../bridge";
import { useApp } from "../stores/app";
import { Button } from "../components/ui";

export function Unlock() {
  const [status, setStatus] = useState<KeyringStatus | null>(null);
  const [lock, setLock] = useState<AppLockStatus | null>(null);
  const [mode, setMode] = useState<"pick" | "phone" | "recovery">("pick");
  const [phoneState, setPhoneState] = useState<"idle" | "waiting">("idle");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const setLocked = useApp((s) => s.setLocked);

  useEffect(() => {
    void bridge.keyringStatus().then(setStatus);
    void lockStatus().then(setLock);
  }, []);

  const unlockBiometric = async () => {
    await bridge.mockBiometricApprove?.();
    await bridge.unlockPlatform();
    setLocked(false);
  };
  const unlockPhone = async () => {
    setMode("phone");
    setPhoneState("waiting");
    const { requestId } = await bridge.unlockPhoneBegin();
    await bridge.unlockPhoneAwait(requestId);
    setLocked(false);
  };
  const unlockRecovery = async () => {
    await bridge.unlockRecovery(recoveryKey);
    setLocked(false);
  };
  const unlockPassword = async () => {
    setBusy(true);
    setError("");
    try {
      await lockUnlockPassword(password, lock?.totpEnabled ? code : undefined);
      setLocked(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setBusy(false);
  };

  const passwordMode = !!lock?.passwordProtected;

  return (
    <div className="relative flex h-full items-center justify-center overflow-hidden">
      {/* Blurred app backdrop */}
      <div className="pointer-events-none absolute inset-0 opacity-40 blur-2xl">
        <div className="absolute left-[15%] top-[20%] h-64 w-64 rounded-full bg-[var(--accent)]/30" />
        <div className="absolute right-[10%] bottom-[15%] h-72 w-72 rounded-full bg-[var(--accent-dim)]/40" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 12, filter: "blur(8px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        transition={{ duration: 0.4 }}
        className="surface-overlay relative z-10 w-[420px] p-8 shadow-2xl"
      >
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent)]/12">
            <Shield className="text-accent" size={28} />
          </div>
          <h1 className="text-xl font-semibold">Vault locked</h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            {passwordMode
              ? lock?.totpEnabled
                ? "Enter your master password and authenticator code."
                : "Enter your master password to continue."
              : "Unlock to continue. Your key is held by your device."}
          </p>
        </div>

        {/* Master-password unlock (real factor) */}
        {passwordMode && (
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              void unlockPassword();
            }}
          >
            <div className="flex items-center gap-2 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3">
              <Lock size={16} className="text-[var(--text-muted)]" />
              <input
                type="password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Master password"
                className="flex-1 bg-transparent py-2.5 text-sm outline-none"
              />
            </div>
            {lock?.totpEnabled && (
              <input
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                placeholder="6-digit authenticator code"
                className="mono rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2.5 text-sm tracking-widest outline-none focus:border-[var(--accent)]"
              />
            )}
            {error && <p className="text-xs text-[var(--danger)]">{error}</p>}
            <Button type="submit" disabled={busy || !password} className="w-full">
              {busy ? "Unlocking…" : "Unlock"}
            </Button>
          </form>
        )}

        {/* Legacy hardware paths (only when no master password is set) */}
        {!passwordMode && mode === "pick" && (
          <div className="flex flex-col gap-2">
            <UnlockRow icon={<Fingerprint size={20} />} title="Touch ID" subtitle="This device" onClick={unlockBiometric} enrolled />
            <UnlockRow icon={<Smartphone size={20} />} title="Approve on iPhone" subtitle="iPhone 16 Pro" onClick={unlockPhone} enrolled={status?.wrappers.find((w) => w.type === "phone")?.enrolled} />
            <UnlockRow icon={<KeyRound size={20} />} title="Recovery kit" subtitle="Break-glass" onClick={() => setMode("recovery")} enrolled />
          </div>
        )}

        {!passwordMode && mode === "phone" && (
          <div className="flex flex-col items-center gap-4 py-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--accent)]/12">
              {phoneState === "waiting" ? <Loader2 className="animate-spin text-accent" size={28} /> : <Smartphone className="text-accent" size={28} />}
            </div>
            <div className="text-center">
              <div className="font-medium">Approve on iPhone</div>
              <div className="mt-1 text-sm text-[var(--text-secondary)]">Face ID prompt sent to iPhone 16 Pro…</div>
            </div>
            <Button variant="ghost" onClick={() => setMode("pick")}>Cancel</Button>
          </div>
        )}

        {!passwordMode && mode === "recovery" && (
          <div className="flex flex-col gap-3">
            <label className="text-sm text-[var(--text-secondary)]">Enter your recovery key</label>
            <input
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
              placeholder="SNTL-XXXXX-XXXXX-…"
              className="mono w-full rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2.5 text-sm outline-none focus:border-[var(--accent)]"
            />
            <div className="flex gap-2">
              <Button variant="ghost" onClick={() => setMode("pick")}>Back</Button>
              <Button onClick={unlockRecovery} className="flex-1">Unlock</Button>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
}

function UnlockRow({ icon, title, subtitle, onClick, enrolled }: { icon: React.ReactNode; title: string; subtitle: string; onClick: () => void; enrolled?: boolean }) {
  return (
    <button
      disabled={!enrolled}
      onClick={onClick}
      className="flex items-center gap-3 rounded-[12px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--accent)]/40 disabled:opacity-40"
    >
      <span className="text-accent">{icon}</span>
      <span className="flex flex-col">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-[var(--text-muted)]">{enrolled ? subtitle : "Not set up"}</span>
      </span>
    </button>
  );
}
