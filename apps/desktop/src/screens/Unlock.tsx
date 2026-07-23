import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Shield, Fingerprint, Lock } from "lucide-react";
import { bridge, lockStatus, lockUnlockPassword, helloStatus, type AppLockStatus } from "../bridge";
import { useApp } from "../stores/app";
import { Button } from "../components/ui";

// The unlock screen offers ONLY real factors: the master password (+ optional authenticator
// code), and the OS biometric when the platform actually has a verifier. The old "Approve on
// iPhone" and "Recovery kit" rows were removed — they ignored their input and re-unlocked from
// the OS keychain, which is worse than not existing. They return when the real flows land.
export function Unlock() {
  const [lock, setLock] = useState<AppLockStatus | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const setLocked = useApp((s) => s.setLocked);

  useEffect(() => {
    void lockStatus().then(setLock);
    // Only offer the biometric row when the OS actually has a verifier (Windows Hello today;
    // Touch ID once wired) — otherwise it's a button that unlocks with no real check.
    void helloStatus().then((h) => setBiometricAvailable(h.available));
  }, []);

  const unlockBiometric = async () => {
    setBusy(true);
    setError("");
    try {
      await bridge.mockBiometricApprove?.();
      await bridge.unlockPlatform();
      setLocked(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
    setBusy(false);
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

        {/* No master password: the OS biometric (when real), else a plain continue. */}
        {!passwordMode && (
          <div className="flex flex-col gap-2">
            {biometricAvailable ? (
              <button
                onClick={() => void unlockBiometric()}
                className="flex items-center gap-3 rounded-[12px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--accent)]/40"
              >
                <span className="text-accent">
                  <Fingerprint size={20} />
                </span>
                <span className="flex flex-col">
                  <span className="text-sm font-medium">Biometric unlock</span>
                  <span className="text-xs text-[var(--text-muted)]">This device</span>
                </span>
              </button>
            ) : (
              <Button onClick={() => void unlockBiometric()} className="w-full">
                Unlock
              </Button>
            )}
            <p className="text-center text-[11px] text-[var(--text-muted)]">
              Add a master password under Settings → Security to protect this vault with a real secret.
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
}
