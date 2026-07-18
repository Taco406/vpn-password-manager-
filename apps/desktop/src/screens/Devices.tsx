import { useEffect, useState } from "react";
import { Laptop, Smartphone, ShieldCheck, QrCode } from "lucide-react";
import type { DeviceInfo } from "@sentinel/shared";
import { bridge } from "../bridge";
import { Card, SectionTitle, Button, Badge } from "../components/ui";

export function Devices() {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [pairing, setPairing] = useState<{ qrPayload: string; verificationCode: string } | null>(null);

  useEffect(() => {
    void bridge.devicesList().then(setDevices);
  }, []);

  const startPair = async () => setPairing(await bridge.pairBegin());

  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <SectionTitle hint="paired hardware">Devices</SectionTitle>

      <div className="flex flex-col gap-2">
        {devices.map((d) => (
          <Card key={d.id} className="!p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-[10px] bg-[var(--bg-inset)] text-accent">
                {d.platform === "ios" ? <Smartphone size={18} /> : <Laptop size={18} />}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 text-sm font-medium">
                  {d.name}
                  {d.current && <Badge tone="accent">This device</Badge>}
                </div>
                <div className="text-xs text-[var(--text-muted)]">{d.platform} · added {new Date(d.createdAt).toLocaleDateString()}</div>
              </div>
              {d.status === "approved" ? <Badge tone="ok"><ShieldCheck size={11} /> Approved</Badge> : <Badge tone="warn">{d.status}</Badge>}
            </div>
          </Card>
        ))}
      </div>

      <Card className="mt-6">
        <div className="flex items-start gap-5">
          <div className="flex h-32 w-32 shrink-0 items-center justify-center rounded-[12px] border border-[var(--border-strong)] bg-[var(--bg-inset)]">
            {pairing ? <QrPlaceholder /> : <QrCode size={40} className="text-[var(--text-muted)]" />}
          </div>
          <div className="flex-1">
            <div className="text-sm font-medium">Pair a new iPhone</div>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              Scan the code with the SENTINEL Key app. Confirm the verification code matches on both screens (out-of-band check — no trust-on-first-use).
            </p>
            {pairing ? (
              <div className="mt-3 flex items-center gap-3">
                <span className="text-xs text-[var(--text-muted)]">Verification code</span>
                <span className="mono text-2xl font-bold tracking-widest text-accent">{pairing.verificationCode}</span>
              </div>
            ) : (
              <Button onClick={startPair} className="mt-3">
                <QrCode size={16} /> Start pairing
              </Button>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}

function QrPlaceholder() {
  // A deterministic faux-QR pattern for the demo.
  const cells = Array.from({ length: 121 }, (_, i) => (i * 37 + (i % 7) * 13) % 3 === 0);
  return (
    <div className="grid grid-cols-11 gap-[2px] p-2">
      {cells.map((on, i) => (
        <div key={i} className="h-2 w-2 rounded-[1px]" style={{ background: on ? "var(--text-primary)" : "transparent" }} />
      ))}
    </div>
  );
}
