import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Check, Fingerprint, KeyRound, Printer, Smartphone, Cloud } from "lucide-react";
import { bridge } from "../bridge";
import { useApp } from "../stores/app";
import { Card, Button, Badge } from "../components/ui";

type Step = "welcome" | "account" | "biometric" | "kit" | "verify" | "done";

export function Onboarding() {
  const [step, setStep] = useState<Step>("welcome");
  const [kit] = useState("SNTL-A6GRV-EXGN8-30WJC-79VXR-WBBQP-S88WR");
  const [g1, setG1] = useState("");
  const [g2, setG2] = useState("");
  const [error, setError] = useState(false);
  const navigate = useNavigate();
  const setLocked = useApp((s) => s.setLocked);

  const groups = kit.replace("SNTL-", "").split("-");
  // Challenge on groups 2 and 5 (indices 1 and 4).
  const verify = async () => {
    if (g1.trim().toUpperCase() === groups[1] && g2.trim().toUpperCase() === groups[4]) {
      await bridge.recoveryKitVerify([{ index: 1, value: g1 }, { index: 4, value: g2 }]);
      setStep("done");
      setLocked(false);
    } else setError(true);
  };

  const finish = () => navigate("/vault");

  return (
    <div className="flex h-full items-center justify-center p-8">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="w-[560px]">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="text-accent" size={26} />
          <span className="text-xl font-bold tracking-tight">Set up SENTINEL</span>
        </div>

        <div className="mb-5 flex items-center gap-2">
          {(["welcome", "account", "biometric", "kit", "verify"] as Step[]).map((s, i) => {
            const order: Step[] = ["welcome", "account", "biometric", "kit", "verify"];
            const done = order.indexOf(step) > i || step === "done";
            const active = step === s;
            return (
              <div key={s} className={`h-1 flex-1 rounded-full ${done ? "bg-[var(--accent)]" : active ? "bg-[var(--accent)]/50" : "bg-[var(--bg-inset)]"}`} />
            );
          })}
        </div>

        {step === "welcome" && (
          <Card>
            <h2 className="text-lg font-semibold">A vault with no master password</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">
              SENTINEL generates a random 256-bit key that never leaves your control. It's wrapped by your device biometric, your iPhone, and a printed recovery kit — never by a password you could forget or reuse.
            </p>
            <div className="mt-4 flex flex-col gap-2">
              <FeatureRow icon={<Fingerprint size={16} />} title="Touch ID" desc="Daily unlock, TPM-backed" />
              <FeatureRow icon={<Smartphone size={16} />} title="iPhone companion" desc="Face ID approval, Secure Enclave" />
              <FeatureRow icon={<Printer size={16} />} title="Recovery kit" desc="Printed break-glass key" />
            </div>
            <Button onClick={() => setStep("account")} className="mt-5 w-full">Get started</Button>
          </Card>
        )}

        {step === "account" && (
          <Card>
            <h2 className="text-lg font-semibold">Sync account (optional)</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">
              Sign in with Google for multi-device sync and iPhone unlock. Everything works offline without it — the server only ever sees encrypted blobs.
            </p>
            <div className="mt-4 flex flex-col gap-2">
              <Button onClick={() => setStep("biometric")} className="w-full"><Cloud size={16} /> Continue with Google</Button>
              <Button variant="ghost" onClick={() => { void bridge.useLocalOnly(); setStep("biometric"); }} className="w-full">Use this device only</Button>
            </div>
          </Card>
        )}

        {step === "biometric" && (
          <Card>
            <h2 className="text-lg font-semibold">Enroll Touch ID</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">Your daily unlock. The vault key is wrapped by a hardware key that never leaves the Secure Enclave.</p>
            <div className="my-6 flex justify-center">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl bg-[var(--accent)]/12">
                <Fingerprint className="text-accent" size={38} />
              </div>
            </div>
            <Button onClick={async () => { await bridge.enrollWrapper("platform"); setStep("kit"); }} className="w-full">Enroll biometric</Button>
          </Card>
        )}

        {step === "kit" && (
          <Card>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Your recovery kit</h2>
              <Badge tone="warn">Shown once</Badge>
            </div>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">Print this and store it safely. It's the only way back in if you lose every device. We never store it.</p>
            <div className="my-4 rounded-[12px] border border-[var(--border-strong)] bg-[var(--bg-inset)] p-4 text-center">
              <div className="mono text-lg font-bold tracking-wide text-accent">{kit}</div>
            </div>
            <div className="flex gap-2">
              <Button variant="ghost" className="flex-1"><Printer size={15} /> Print PDF</Button>
              <Button onClick={() => setStep("verify")} className="flex-1">I've saved it</Button>
            </div>
          </Card>
        )}

        {step === "verify" && (
          <Card>
            <h2 className="text-lg font-semibold">Confirm your recovery kit</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">Re-enter two groups from your printed kit. The vault stays locked until you prove you saved it.</p>
            <div className="mt-4 flex flex-col gap-3">
              <GroupInput n={2} value={g1} onChange={(v) => { setG1(v); setError(false); }} />
              <GroupInput n={5} value={g2} onChange={(v) => { setG2(v); setError(false); }} />
              {error && <div className="text-xs text-[var(--danger)]">Those groups don't match. Check your printed kit.</div>}
            </div>
            <Button onClick={verify} className="mt-4 w-full">Verify &amp; activate vault</Button>
          </Card>
        )}

        {step === "done" && (
          <Card className="accent-glow text-center">
            <div className="mx-auto mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--ok)]/15">
              <Check className="text-[var(--ok)]" size={32} />
            </div>
            <h2 className="text-lg font-semibold">Vault active</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">Your recovery kit is verified and your key is protected. You're all set.</p>
            <Button onClick={finish} className="mt-5 w-full">Open vault</Button>
          </Card>
        )}
      </motion.div>
    </div>
  );
}

function FeatureRow({ icon, title, desc }: { icon: React.ReactNode; title: string; desc: string }) {
  return (
    <div className="flex items-center gap-3 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2.5">
      <span className="text-accent">{icon}</span>
      <div className="flex-1">
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-[var(--text-muted)]">{desc}</div>
      </div>
    </div>
  );
}

function GroupInput({ n, value, onChange }: { n: number; value: string; onChange: (v: string) => void }) {
  return (
    <label className="flex items-center gap-3">
      <span className="mono w-16 shrink-0 text-xs text-[var(--text-muted)]">Group {n}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="XXXXX"
        maxLength={5}
        className="mono w-full rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-2.5 text-sm uppercase tracking-widest outline-none focus:border-[var(--accent)]"
      />
    </label>
  );
}
