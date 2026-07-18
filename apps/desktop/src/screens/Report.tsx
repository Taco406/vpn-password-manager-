import { useEffect, useState } from "react";
import { Download, TrendingUp, Clock, Database, PiggyBank } from "lucide-react";
import type { ReportData } from "@sentinel/shared";
import { bridge } from "../bridge";
import { fmtBytes } from "../components/charts/ThroughputChart";
import { Card, SectionTitle, Stat, Button, Badge } from "../components/ui";

const MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const REGION_COLORS = ["#22d3ee", "#0891b2", "#38def6", "#0e7490", "#7dd3fc", "#164e63"];

export function Report() {
  const [r, setR] = useState<ReportData | null>(null);
  useEffect(() => {
    void bridge.reportMonth(2026, 6).then(setR);
  }, []);
  if (!r) return null;

  const saved = r.commercialVpnUsd - r.costUsd;
  const totalHours = r.byRegion.reduce((a, x) => a + x.hours, 0) || 1;

  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <div className="flex items-center justify-between">
        <SectionTitle hint={`${MONTHS[r.month]} ${r.year}`}>Monthly report card</SectionTitle>
        <Button variant="ghost"><Download size={15} /> Export PNG</Button>
      </div>

      <Card className="mb-4 accent-glow">
        <div className="grid grid-cols-4 gap-4">
          <Stat label="Sessions" value={String(r.sessions)} />
          <Stat label="Hours" value={r.hours.toFixed(1)} />
          <Stat label="Data" value={fmtBytes(r.bytesTotal)} mono={false} />
          <Stat label="Cost" value={`$${r.costUsd.toFixed(2)}`} />
        </div>
      </Card>

      <Card className="mb-4">
        <div className="flex items-center gap-3">
          <PiggyBank className="text-[var(--ok)]" size={22} />
          <div className="flex-1">
            <div className="text-sm font-medium">You saved ${saved.toFixed(2)} this month</div>
            <div className="text-xs text-[var(--text-muted)]">${r.costUsd.toFixed(2)} self-hosted vs ${r.commercialVpnUsd.toFixed(2)} for a commercial VPN subscription</div>
          </div>
          <Badge tone="ok">{Math.round((saved / r.commercialVpnUsd) * 100)}% cheaper</Badge>
        </div>
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-[var(--bg-inset)]">
          <div className="h-full rounded-full bg-[var(--ok)]" style={{ width: `${(r.costUsd / r.commercialVpnUsd) * 100}%` }} />
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <div className="mb-3 text-sm font-medium">Time by region</div>
          <div className="flex flex-col gap-2">
            {r.byRegion.map((br, i) => (
              <div key={br.region}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="text-[var(--text-secondary)]">{br.region}</span>
                  <span className="mono text-[var(--text-muted)]">{br.hours.toFixed(1)}h</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-[var(--bg-inset)]">
                  <div className="h-full rounded-full" style={{ width: `${(br.hours / totalHours) * 100}%`, background: REGION_COLORS[i % REGION_COLORS.length] }} />
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <div className="mb-3 text-sm font-medium">Speed range</div>
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <TrendingUp size={18} className="text-[var(--ok)]" />
              <div>
                <div className="mono text-2xl font-semibold">{r.bestDownMbps}<span className="text-sm font-normal"> Mbps</span></div>
                <div className="text-xs text-[var(--text-muted)]">Best download</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <TrendingUp size={18} className="rotate-180 text-[var(--text-muted)]" />
              <div>
                <div className="mono text-2xl font-semibold">{r.worstDownMbps}<span className="text-sm font-normal"> Mbps</span></div>
                <div className="text-xs text-[var(--text-muted)]">Worst download</div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <div className="mt-6 flex items-center gap-6 text-xs text-[var(--text-muted)]">
        <span className="flex items-center gap-1.5"><Clock size={12} /> {r.hours.toFixed(1)} hours protected</span>
        <span className="flex items-center gap-1.5"><Database size={12} /> {fmtBytes(r.bytesTotal)} transferred</span>
      </div>
    </div>
  );
}
