import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Download, TrendingUp, Clock, Database, PiggyBank, ChevronLeft, ChevronRight } from "lucide-react";
import type { ReportData } from "@sentinel/shared";
import { bridge } from "../bridge";
import { fmtBytes } from "../components/charts/ThroughputChart";
import { Card, SectionTitle, Stat, Button, Badge } from "../components/ui";
import { toastError, toastSuccess } from "../components/Toast";

const MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const REGION_COLORS = ["#22d3ee", "#0891b2", "#38def6", "#0e7490", "#7dd3fc", "#164e63"];

const ym = (year: number, month: number) => `${year}-${String(month).padStart(2, "0")}`;

export function Report() {
  const { ym: ymParam } = useParams();
  const navigate = useNavigate();

  // Honor the month in the URL (`/report/YYYY-MM`); default to the current month.
  const nowD = new Date();
  let year = nowD.getFullYear();
  let month = nowD.getMonth() + 1;
  if (ymParam && /^\d{4}-\d{2}$/.test(ymParam)) {
    const [y, m] = ymParam.split("-").map(Number);
    year = y;
    month = m;
  }

  const [r, setR] = useState<ReportData | null>(null);
  useEffect(() => {
    setR(null);
    bridge.reportMonth(year, month).then(setR).catch(toastError);
  }, [year, month]);

  const goMonth = (delta: number) => {
    let y = year;
    let m = month + delta;
    if (m < 1) {
      m = 12;
      y -= 1;
    } else if (m > 12) {
      m = 1;
      y += 1;
    }
    navigate(`/report/${ym(y, m)}`);
  };

  if (!r)
    return (
      <div className="mx-auto max-w-3xl px-8 py-8 text-sm text-[var(--text-muted)]">Loading report…</div>
    );

  const saved = r.commercialVpnUsd - r.costUsd;
  const totalHours = r.byRegion.reduce((a, x) => a + x.hours, 0) || 1;

  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <div className="flex items-center justify-between">
        <SectionTitle hint={`${MONTHS[r.month]} ${r.year}`}>Monthly report card</SectionTitle>
        <div className="flex items-center gap-1">
          <button onClick={() => goMonth(-1)} aria-label="Previous month" className="rounded-[8px] border border-[var(--border-strong)] p-1.5 hover:border-[var(--accent)]/50">
            <ChevronLeft size={15} />
          </button>
          <button onClick={() => goMonth(1)} aria-label="Next month" className="rounded-[8px] border border-[var(--border-strong)] p-1.5 hover:border-[var(--accent)]/50">
            <ChevronRight size={15} />
          </button>
          <Button variant="ghost" onClick={() => exportReportPng(r)}>
            <Download size={15} /> Export PNG
          </Button>
        </div>
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

/** Render the report to a shareable PNG on an offscreen canvas (dependency-free — we draw the
 * numbers directly, so it's reliable regardless of DOM/CSS) and download it. */
function exportReportPng(r: ReportData) {
  const W = 900;
  const H = 540;
  const S = 2;
  const canvas = document.createElement("canvas");
  canvas.width = W * S;
  canvas.height = H * S;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.scale(S, S);

  const BG = "#0A0E14";
  const CARD = "#0F141C";
  const ACC = "#22D3EE";
  const OK = "#2ED47A";
  const TXT = "#E6EDF3";
  const MUT = "#8290A0";
  const INSET = "#161C26";
  const sans = (px: number, w = "400") => `${w} ${px}px -apple-system, "Segoe UI", Roboto, sans-serif`;
  const mono = (px: number, w = "600") => `${w} ${px}px ui-monospace, SFMono-Regular, Menlo, monospace`;
  const roundRect = (x: number, y: number, w: number, h: number, rad: number) => {
    ctx.beginPath();
    // roundRect is unavailable on older WebKit (Tauri macOS); square corners are a fine fallback.
    if (typeof ctx.roundRect === "function") ctx.roundRect(x, y, w, h, rad);
    else ctx.rect(x, y, w, h);
  };

  ctx.fillStyle = BG;
  ctx.fillRect(0, 0, W, H);

  // Header
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = TXT;
  ctx.font = sans(22, "700");
  ctx.fillText("NORTHKEY", 40, 52);
  ctx.fillStyle = MUT;
  ctx.font = sans(15);
  ctx.fillText(`Monthly report — ${MONTHS[r.month]} ${r.year}`, 40, 74);

  // Stat tiles
  const stats: [string, string][] = [
    ["Sessions", String(r.sessions)],
    ["Hours", r.hours.toFixed(1)],
    ["Data", fmtBytes(r.bytesTotal)],
    ["Cost", `$${r.costUsd.toFixed(2)}`],
  ];
  const tileW = (W - 80 - 3 * 16) / 4;
  stats.forEach(([label, value], i) => {
    const x = 40 + i * (tileW + 16);
    ctx.fillStyle = CARD;
    roundRect(x, 100, tileW, 90, 12);
    ctx.fill();
    ctx.fillStyle = MUT;
    ctx.font = sans(11, "600");
    ctx.fillText(label.toUpperCase(), x + 16, 128);
    ctx.fillStyle = TXT;
    ctx.font = mono(26, "700");
    ctx.fillText(value, x + 16, 166);
  });

  // Savings
  ctx.fillStyle = CARD;
  roundRect(40, 208, W - 80, 78, 12);
  ctx.fill();
  const saved = r.commercialVpnUsd - r.costUsd;
  ctx.fillStyle = OK;
  ctx.font = sans(16, "700");
  ctx.fillText(`You saved $${saved.toFixed(2)} this month`, 60, 240);
  ctx.fillStyle = MUT;
  ctx.font = sans(13);
  ctx.fillText(
    `$${r.costUsd.toFixed(2)} self-hosted vs $${r.commercialVpnUsd.toFixed(2)} for a commercial VPN`,
    60,
    262,
  );
  ctx.fillStyle = INSET;
  roundRect(60, 272, W - 120, 6, 3);
  ctx.fill();
  ctx.fillStyle = OK;
  const pct = r.commercialVpnUsd > 0 ? r.costUsd / r.commercialVpnUsd : 0;
  roundRect(60, 272, Math.max(0, (W - 120) * Math.min(1, pct)), 6, 3);
  ctx.fill();

  // Time by region
  ctx.fillStyle = TXT;
  ctx.font = sans(14, "600");
  ctx.fillText("Time by region", 40, 328);
  const total = r.byRegion.reduce((a, x) => a + x.hours, 0) || 1;
  r.byRegion.slice(0, 5).forEach((br, i) => {
    const y = 348 + i * 30;
    ctx.fillStyle = MUT;
    ctx.font = sans(12);
    ctx.fillText(br.region, 40, y + 4);
    ctx.font = mono(12, "500");
    ctx.textAlign = "right";
    ctx.fillText(`${br.hours.toFixed(1)}h`, W - 40, y + 4);
    ctx.textAlign = "left";
    ctx.fillStyle = INSET;
    roundRect(40, y + 10, W - 80, 6, 3);
    ctx.fill();
    ctx.fillStyle = REGION_COLORS[i % REGION_COLORS.length];
    roundRect(40, y + 10, (W - 80) * (br.hours / total), 6, 3);
    ctx.fill();
  });

  // Footer
  ctx.fillStyle = MUT;
  ctx.font = sans(12);
  ctx.fillText(
    `${r.hours.toFixed(1)} hours protected  ·  ${fmtBytes(r.bytesTotal)} transferred  ·  best ${r.bestDownMbps} Mbps`,
    40,
    H - 28,
  );

  canvas.toBlob((blob) => {
    if (!blob) {
      toastError("Could not render the report image.");
      return;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `northkey-report-${ym(r.year, r.month)}.png`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastSuccess("Report saved as a PNG.");
  }, "image/png");
}
