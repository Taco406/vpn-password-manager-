import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Copy as CopyIcon,
  RefreshCw,
  Repeat,
  ShieldAlert,
  Clock,
  Flame,
  Check,
  ExternalLink,
  Loader2,
} from "lucide-react";
import type { AuditReport, GeneratedPassword, ItemSummary } from "@sentinel/shared";
import { bridge, healthAuditFast, openUrl } from "../bridge";
import { Card, SectionTitle, Button, Badge } from "../components/ui";

export function Health() {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [items, setItems] = useState<Record<string, ItemSummary>>({});
  // The fast (local-only) audit lands first so the tab renders immediately; the full audit
  // (which does the network HIBP breach check) arrives after and fills in the breach counts.
  const [breachChecked, setBreachChecked] = useState(false);

  useEffect(() => {
    // Render instantly from the local audit (reused / weak / old — no network)…
    void healthAuditFast().then(setReport);
    // …then replace with the breach-aware full audit once the HIBP check returns.
    void bridge.healthAudit().then((full) => {
      setReport(full);
      setBreachChecked(true);
    });
    void bridge.vaultList().then((list) => setItems(Object.fromEntries(list.map((i) => [i.id, i]))));
  }, []);

  const title = (id: string) => items[id]?.title ?? id;
  const domainOf = (id: string) => items[id]?.faviconDomain;

  // "Fix" a credential: mint a fresh strong password, copy it to the clipboard, and open the
  // site's standard change-password page (/.well-known/change-password, which every major site
  // redirects to its real reset form) so the user can paste the new one straight in.
  const fixItem = async (id: string) => {
    const pw = await bridge.generatorPassword({
      length: 20,
      lower: true,
      upper: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: false,
    });
    await navigator.clipboard?.writeText(pw.value);
    const domain = domainOf(id);
    if (domain) await openUrl(`https://${domain}/.well-known/change-password`);
  };

  return (
    <div className="mx-auto max-w-4xl px-8 py-8">
      <SectionTitle hint="reused · weak · old · breached">Vault health</SectionTitle>

      {!report ? (
        <Card className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
          <Loader2 size={15} className="animate-spin" /> Analyzing your vault…
        </Card>
      ) : (
        <div className="grid grid-cols-[220px_1fr] gap-6">
          <ScoreRing score={report.score} />
          <div className="grid grid-cols-2 gap-3">
            <Metric icon={<Repeat size={15} />} tone="warn" n={report.reused.reduce((a, g) => a + g.itemIds.length, 0)} label="Reused" />
            <Metric icon={<ShieldAlert size={15} />} tone="warn" n={report.weak.length} label="Weak" />
            <Metric icon={<Clock size={15} />} tone="neutral" n={report.old.length} label="Old (>180d)" />
            <Metric
              icon={breachChecked ? <Flame size={15} /> : <Loader2 size={15} className="animate-spin" />}
              tone="danger"
              n={report.breached.length}
              label={breachChecked ? "Breached" : "Checking…"}
            />
          </div>
        </div>
      )}

      {report && (report.breached.length > 0 || report.reused.length > 0 || report.weak.length > 0) && (
        <div className="mt-6 flex flex-col gap-4">
          <p className="text-xs text-[var(--text-muted)]">
            <span className="text-[var(--text-secondary)]">Fix</span> copies a fresh strong password and opens that
            site's password-change page so you can paste it in.
          </p>
          {report.breached.length > 0 && (
            <Card>
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-[var(--danger)]">
                <Flame size={15} /> Found in known breaches
              </div>
              {report.breached.map((b) => (
                <Row
                  key={b.itemId}
                  title={title(b.itemId)}
                  right={
                    <>
                      <Badge tone="danger">{b.count.toLocaleString()} hits</Badge>
                      <FixButton id={b.itemId} domain={domainOf(b.itemId)} onFix={fixItem} />
                    </>
                  }
                />
              ))}
            </Card>
          )}
          {report.reused.length > 0 && (
            <Card>
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-[var(--warn)]">
                <Repeat size={15} /> Reused across sites
              </div>
              {report.reused.flatMap((g) =>
                g.itemIds.map((id) => (
                  <Row
                    key={id}
                    title={title(id)}
                    right={
                      <>
                        <Badge tone="warn">{g.itemIds.length}×</Badge>
                        <FixButton id={id} domain={domainOf(id)} onFix={fixItem} />
                      </>
                    }
                  />
                )),
              )}
            </Card>
          )}
          {report.weak.length > 0 && (
            <Card>
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-[var(--warn)]">
                <AlertTriangle size={15} /> Weak passwords
              </div>
              {report.weak.map((w) => (
                <Row
                  key={w.itemId}
                  title={title(w.itemId)}
                  right={
                    <>
                      <Badge tone="warn">score {w.score}/4</Badge>
                      <FixButton id={w.itemId} domain={domainOf(w.itemId)} onFix={fixItem} />
                    </>
                  }
                />
              ))}
            </Card>
          )}
        </div>
      )}

      <Generator />
    </div>
  );
}

function FixButton({ id, domain, onFix }: { id: string; domain?: string; onFix: (id: string) => Promise<void> }) {
  const [done, setDone] = useState(false);
  const click = async () => {
    await onFix(id);
    setDone(true);
    window.setTimeout(() => setDone(false), 2500);
  };
  return (
    <Button variant="ghost" onClick={click} className="!px-2.5 !py-1 text-xs">
      {done ? (
        <>
          <Check size={13} /> Copied
        </>
      ) : domain ? (
        <>
          <ExternalLink size={13} /> Fix
        </>
      ) : (
        <>
          <CopyIcon size={13} /> New password
        </>
      )}
    </Button>
  );
}

function ScoreRing({ score }: { score: number }) {
  const r = 70;
  const c = 2 * Math.PI * r;
  const tone = score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--danger)";
  return (
    <Card className="flex flex-col items-center justify-center">
      <svg width="170" height="170" viewBox="0 0 170 170" className="-rotate-90">
        <circle cx="85" cy="85" r={r} fill="none" stroke="var(--bg-inset)" strokeWidth="12" />
        <circle cx="85" cy="85" r={r} fill="none" stroke={tone} strokeWidth="12" strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} strokeLinecap="round" />
      </svg>
      <div className="-mt-[108px] flex flex-col items-center">
        <span className="mono text-4xl font-bold">{score}</span>
        <span className="text-xs text-[var(--text-muted)]">/ 100</span>
      </div>
      <div className="mt-[64px] text-sm text-[var(--text-secondary)]">Overall health</div>
    </Card>
  );
}

function Metric({ icon, n, label, tone }: { icon: React.ReactNode; n: number; label: string; tone: "warn" | "danger" | "neutral" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warn" ? "var(--warn)" : "var(--text-secondary)";
  return (
    <Card className="!p-4">
      <div className="flex items-center gap-1.5 text-xs" style={{ color }}>{icon} {label}</div>
      <div className="mono mt-1 text-2xl font-semibold">{n}</div>
    </Card>
  );
}

function Row({ title, right }: { title: string; right: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-[var(--border-subtle)] py-2 first:border-0">
      <span className="truncate text-sm">{title}</span>
      <div className="flex shrink-0 items-center gap-2">{right}</div>
    </div>
  );
}

function Generator() {
  const [pw, setPw] = useState<GeneratedPassword | null>(null);
  const [mode, setMode] = useState<"charset" | "passphrase">("charset");
  const [length, setLength] = useState(20);

  const gen = async () => {
    if (mode === "charset")
      setPw(await bridge.generatorPassword({ length, lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: false }));
    else setPw(await bridge.generatorPassphrase({ words: 6, separator: "-", capitalize: true, includeNumber: true }));
  };
  useEffect(() => {
    void gen();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, length]);

  const strength = ["Very weak", "Weak", "Fair", "Strong", "Excellent"][pw?.score ?? 0];
  const tone = (pw?.score ?? 0) >= 3 ? "ok" : (pw?.score ?? 0) >= 2 ? "warn" : "danger";

  return (
    <Card className="mt-6">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium">Password generator</span>
        <div className="flex gap-1 rounded-[8px] bg-[var(--bg-inset)] p-0.5 text-xs">
          {(["charset", "passphrase"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)} className={`rounded-[6px] px-2.5 py-1 ${mode === m ? "bg-[var(--accent)]/15 text-[var(--accent)]" : "text-[var(--text-muted)]"}`}>
              {m === "charset" ? "Random" : "Passphrase"}
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-3 py-3">
        <span className="mono flex-1 break-all text-sm text-accent">{pw?.value}</span>
        <button onClick={() => navigator.clipboard?.writeText(pw?.value ?? "")} className="text-[var(--text-muted)] hover:text-[var(--accent)]"><CopyIcon size={16} /></button>
        <button onClick={gen} className="text-[var(--text-muted)] hover:text-[var(--accent)]"><RefreshCw size={16} /></button>
      </div>
      <div className="mt-3 flex items-center justify-between">
        <Badge tone={tone as "ok" | "warn" | "danger"}>{strength}</Badge>
        {mode === "charset" && (
          <label className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
            length {length}
            <input type="range" min={8} max={48} value={length} onChange={(e) => setLength(+e.target.value)} className="accent-[var(--accent)]" />
          </label>
        )}
        <span className="mono text-xs text-[var(--text-muted)]">crack: {pw?.crackDisplay}</span>
      </div>
    </Card>
  );
}
