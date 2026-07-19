// A 60fps rolling throughput chart drawn on a 2D canvas: glow-stroke line over a
// gradient area fill, Catmull-Rom smoothed. No chart library.

import { useEffect, useRef } from "react";

function cssVar(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export function ThroughputChart({
  data,
  width = 640,
  height = 200,
  color,
}: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const dataRef = useRef<number[]>(data);
  dataRef.current = data;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);
    const frozen = document.documentElement.getAttribute("data-freeze") === "1";
    let raf = 0;

    function draw() {
      const series = dataRef.current;
      const accent = color ?? cssVar("--accent", "#22d3ee");
      ctx.clearRect(0, 0, width, height);

      // Grid lines.
      ctx.strokeStyle = cssVar("--border-subtle", "#1c2531");
      ctx.lineWidth = 1;
      for (let i = 1; i < 4; i++) {
        const y = (height / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      if (series.length >= 2) {
        const max = Math.max(...series, 1) * 1.15;
        const n = series.length;
        const stepX = width / Math.max(1, n - 1);
        const pts: [number, number][] = series.map((v, i) => [i * stepX, height - (v / max) * (height - 12) - 6]);

        // Smooth path (Catmull-Rom → bezier).
        const linePath = () => {
          ctx.beginPath();
          ctx.moveTo(pts[0][0], pts[0][1]);
          for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] ?? pts[i];
            const p1 = pts[i];
            const p2 = pts[i + 1];
            const p3 = pts[i + 2] ?? p2;
            const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
            const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
            const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
            const cp2y = p2[1] - (p3[1] - p1[1]) / 6;
            ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2[0], p2[1]);
          }
        };

        // Area fill.
        linePath();
        ctx.lineTo(pts[pts.length - 1][0], height);
        ctx.lineTo(pts[0][0], height);
        ctx.closePath();
        const grad = ctx.createLinearGradient(0, 0, 0, height);
        grad.addColorStop(0, accent + "44");
        grad.addColorStop(1, accent + "00");
        ctx.fillStyle = grad;
        ctx.fill();

        // Glow pass then crisp line.
        linePath();
        ctx.strokeStyle = accent;
        ctx.lineWidth = 2.5;
        ctx.shadowColor = accent;
        ctx.shadowBlur = 10;
        ctx.stroke();
        ctx.shadowBlur = 0;
        linePath();
        ctx.strokeStyle = accent;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Leading dot.
        const last = pts[pts.length - 1];
        ctx.beginPath();
        ctx.arc(last[0], last[1], 3, 0, Math.PI * 2);
        ctx.fillStyle = accent;
        ctx.fill();
      }

      if (!frozen) raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [width, height, color]);

  // Display responsively: the canvas renders at its intrinsic `width` but is CSS-scaled to fill
  // (never exceed) its container, so it can't overflow a narrow panel. maxWidth caps it on wide ones.
  return (
    <canvas
      ref={canvasRef}
      style={{ width: "100%", maxWidth: width, height, display: "block" }}
      aria-label="Throughput chart"
    />
  );
}

/** Format bytes/sec into a compact human string. */
export function fmtRate(bytesPerSec: number): { value: string; unit: string } {
  const bits = bytesPerSec * 8;
  if (bits >= 1e9) return { value: (bits / 1e9).toFixed(2), unit: "Gbps" };
  if (bits >= 1e6) return { value: (bits / 1e6).toFixed(1), unit: "Mbps" };
  if (bits >= 1e3) return { value: (bits / 1e3).toFixed(0), unit: "Kbps" };
  return { value: bits.toFixed(0), unit: "bps" };
}

export function fmtBytes(bytes: number): string {
  if (bytes >= 1e12) return (bytes / 1e12).toFixed(2) + " TB";
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + " GB";
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + " MB";
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(0) + " KB";
  return bytes + " B";
}
