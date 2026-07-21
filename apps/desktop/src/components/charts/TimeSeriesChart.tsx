// A fixed-window, time-axis line chart for historical server metrics (CPU %, network,
// disk IO). Sibling of ThroughputChart, same hand-rolled canvas look (Catmull-Rom line
// over a gradient fill) — but it draws on data change instead of every frame, supports
// multiple series with a small legend, and labels both axes. No chart library.

import { useEffect, useRef } from "react";
import { fmtRate } from "./ThroughputChart";

function cssVar(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export interface TimeSeries {
  /** `[unixSeconds, value]` pairs, ascending. */
  points: [number, number][];
  color: string;
  label: string;
}

/** Format a metric value for the axis by unit kind. */
function fmtValue(v: number, unit: "pct" | "bps" | "iops"): string {
  if (unit === "pct") return `${Math.round(v)}%`;
  if (unit === "bps") {
    const r = fmtRate(v);
    return `${r.value} ${r.unit}`;
  }
  return v >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${Math.round(v)}`;
}

export function TimeSeriesChart({
  series,
  height = 150,
  width = 560,
  unit,
}: {
  series: TimeSeries[];
  height?: number;
  width?: number;
  unit: "pct" | "bps" | "iops";
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);

    const padL = 44; // room for value labels
    const padB = 16; // room for time labels
    const plotW = width - padL - 4;
    const plotH = height - padB - 6;

    ctx.clearRect(0, 0, width, height);

    const all = series.flatMap((s) => s.points);
    if (all.length < 2) {
      ctx.fillStyle = cssVar("--text-muted", "#64748b");
      ctx.font = "11px system-ui";
      ctx.fillText("no data", padL + 8, height / 2);
      return;
    }
    const tMin = Math.min(...all.map((p) => p[0]));
    const tMax = Math.max(...all.map((p) => p[0]));
    const vMax = unit === "pct" ? 100 : Math.max(...all.map((p) => p[1]), 1) * 1.15;
    const tSpan = Math.max(1, tMax - tMin);

    const x = (t: number) => padL + ((t - tMin) / tSpan) * plotW;
    const y = (v: number) => 6 + plotH - (Math.min(v, vMax) / vMax) * plotH;

    // Grid + value labels (4 lines).
    ctx.strokeStyle = cssVar("--border-subtle", "#1c2531");
    ctx.fillStyle = cssVar("--text-muted", "#64748b");
    ctx.font = "10px system-ui";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const gy = 6 + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padL, gy);
      ctx.lineTo(width - 4, gy);
      ctx.stroke();
      const v = vMax * (1 - i / 4);
      ctx.fillText(fmtValue(v, unit), 2, gy + 3);
    }

    // Time labels: start / middle / end as HH:MM.
    const hhmm = (t: number) => {
      const d = new Date(t * 1000);
      return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    };
    ctx.textAlign = "center";
    for (const frac of [0, 0.5, 1]) {
      const t = tMin + tSpan * frac;
      ctx.fillText(hhmm(t), x(t), height - 4);
    }
    ctx.textAlign = "start";

    // Series lines (Catmull-Rom → bezier, same feel as ThroughputChart).
    for (const s of series) {
      if (s.points.length < 2) continue;
      const pts: [number, number][] = s.points.map(([t, v]) => [x(t), y(v)]);
      const linePath = () => {
        ctx.beginPath();
        ctx.moveTo(pts[0][0], pts[0][1]);
        for (let i = 0; i < pts.length - 1; i++) {
          const p0 = pts[i - 1] ?? pts[i];
          const p1 = pts[i];
          const p2 = pts[i + 1];
          const p3 = pts[i + 2] ?? p2;
          ctx.bezierCurveTo(
            p1[0] + (p2[0] - p0[0]) / 6,
            p1[1] + (p2[1] - p0[1]) / 6,
            p2[0] - (p3[0] - p1[0]) / 6,
            p2[1] - (p3[1] - p1[1]) / 6,
            p2[0],
            p2[1],
          );
        }
      };
      // Fill only the first series (keeps stacked-look clutter down with two lines).
      if (s === series[0]) {
        linePath();
        ctx.lineTo(pts[pts.length - 1][0], 6 + plotH);
        ctx.lineTo(pts[0][0], 6 + plotH);
        ctx.closePath();
        const grad = ctx.createLinearGradient(0, 0, 0, height);
        grad.addColorStop(0, s.color + "33");
        grad.addColorStop(1, s.color + "00");
        ctx.fillStyle = grad;
        ctx.fill();
      }
      linePath();
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
    }
  }, [series, width, height, unit]);

  return (
    <div>
      <canvas
        ref={canvasRef}
        style={{ width: "100%", maxWidth: width, height, display: "block" }}
        aria-label="Metrics chart"
      />
      {series.length > 1 && (
        <div className="mt-1 flex gap-3 text-[10px] text-[var(--text-muted)]">
          {series.map((s) => (
            <span key={s.label} className="flex items-center gap-1">
              <span className="inline-block h-1.5 w-3 rounded-sm" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
