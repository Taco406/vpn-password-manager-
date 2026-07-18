// The connection globe: a 2D-canvas orthographic projection (d3-geo, no WebGL — see
// DECISIONS D13). Idle rotation, a pulse + great-circle arc on connect, and a settle
// on connected. Honors data-freeze for pixel-stable screenshots.

import { useEffect, useRef } from "react";
import { geoOrthographic, geoPath, geoGraticule10, geoInterpolate, geoCircle } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import type { Region } from "@sentinel/shared";

type Stage = "idle" | "connecting" | "connected";

// "You" — an approximate home location (NYC), used as the arc origin.
const YOU: [number, number] = [-74.0, 40.7];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const land: any = feature(world as any, (world as any).objects.countries);

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#22d3ee";
}

export function Globe({
  regions,
  selectedRegionId,
  stage,
  size = 460,
}: {
  regions: Region[];
  selectedRegionId?: string;
  stage: Stage;
  size?: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const startRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);

    const frozen = document.documentElement.getAttribute("data-freeze") === "1";
    const selected = regions.find((r) => r.id === selectedRegionId);
    const target: [number, number] | null = selected ? [selected.lon, selected.lat] : null;

    const accent = cssVar("--accent");
    const landFill = cssVar("--bg-overlay");
    const isLight = document.documentElement.getAttribute("data-theme") === "light";

    const projection = geoOrthographic()
      .scale(size / 2 - 6)
      .translate([size / 2, size / 2])
      .clipAngle(90);

    const path = geoPath(projection, ctx);

    // Rotate so the selected region (or a default) faces the viewer.
    const focus = target ?? [-30, 20];
    const baseRotate: [number, number] = [-focus[0], -focus[1]];

    function project(lonlat: [number, number]): [number, number] | null {
      const p = projection(lonlat);
      return p ?? null;
    }

    function visible(lonlat: [number, number]): boolean {
      // A point is on the near hemisphere if its projection exists and geoPath draws it.
      const c = projection.rotate();
      const cx = -c[0];
      const cy = -c[1];
      const d = geoInterpolate(lonlat, [cx, cy]);
      // distance via central angle
      const [l1, p1] = lonlat.map((v) => (v * Math.PI) / 180);
      const [l2, p2] = [cx, cy].map((v) => (v * Math.PI) / 180);
      const ang = Math.acos(Math.min(1, Math.sin(p1) * Math.sin(p2) + Math.cos(p1) * Math.cos(p2) * Math.cos(l2 - l1)));
      void d;
      return ang < Math.PI / 2;
    }

    function draw(now: number) {
      if (!startRef.current) startRef.current = now;
      const elapsed = frozen ? 6200 : now - startRef.current;
      const spin = frozen ? 0 : stage === "idle" ? elapsed * 0.004 : 0;
      projection.rotate([baseRotate[0] + spin, baseRotate[1]]);

      ctx.clearRect(0, 0, size, size);

      // Sphere gradient.
      const grad = ctx.createRadialGradient(size * 0.4, size * 0.35, size * 0.1, size / 2, size / 2, size / 2);
      grad.addColorStop(0, isLight ? "#e8eef5" : "#101826");
      grad.addColorStop(1, isLight ? "#d3dce7" : "#0a0e14");
      ctx.beginPath();
      path({ type: "Sphere" });
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.strokeStyle = accent + "33";
      ctx.lineWidth = 1;
      ctx.stroke();

      // Graticule.
      ctx.beginPath();
      path(geoGraticule10());
      ctx.strokeStyle = isLight ? "#00000010" : "#ffffff10";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // Land.
      ctx.beginPath();
      path(land);
      ctx.fillStyle = landFill;
      ctx.fill();
      ctx.strokeStyle = accent + "22";
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // Region dots.
      for (const r of regions) {
        if (!visible([r.lon, r.lat])) continue;
        const p = project([r.lon, r.lat]);
        if (!p) continue;
        const isSel = r.id === selectedRegionId;
        ctx.beginPath();
        ctx.arc(p[0], p[1], isSel ? 4 : 2.2, 0, Math.PI * 2);
        ctx.fillStyle = isSel ? accent : accent + "88";
        ctx.fill();
      }

      // Connect pulse + arc.
      if ((stage === "connecting" || stage === "connected") && target && visible(target)) {
        const tp = project(target);
        if (tp) {
          const phase = frozen ? 0.55 : (elapsed % 1800) / 1800;
          for (let i = 0; i < 3; i++) {
            const rp = ((phase + i / 3) % 1) * 26;
            ctx.beginPath();
            ctx.arc(tp[0], tp[1], 4 + rp, 0, Math.PI * 2);
            ctx.strokeStyle = accent + Math.floor((1 - rp / 30) * 180).toString(16).padStart(2, "0");
            ctx.lineWidth = 1.5;
            ctx.stroke();
          }
          // Great-circle arc from YOU to target.
          if (visible(YOU)) {
            const interp = geoInterpolate(YOU, target);
            ctx.beginPath();
            let started = false;
            const steps = 48;
            const head = frozen ? steps : Math.floor(((elapsed % 2000) / 2000) * steps) + 1;
            for (let i = 0; i <= Math.min(head, steps); i++) {
              const pt = project(interp(i / steps) as [number, number]);
              if (!pt) continue;
              if (!started) {
                ctx.moveTo(pt[0], pt[1]);
                started = true;
              } else ctx.lineTo(pt[0], pt[1]);
            }
            ctx.strokeStyle = accent;
            ctx.lineWidth = 2;
            ctx.shadowColor = accent;
            ctx.shadowBlur = 8;
            ctx.stroke();
            ctx.shadowBlur = 0;
          }
          // Connected halo.
          if (stage === "connected") {
            ctx.beginPath();
            const circle = geoCircle().center(target).radius(3)();
            path(circle);
            ctx.strokeStyle = accent + "66";
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      if (!frozen) rafRef.current = requestAnimationFrame(draw);
    }

    rafRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafRef.current);
  }, [regions, selectedRegionId, stage, size]);

  return <canvas ref={canvasRef} style={{ width: size, height: size }} aria-label="Region globe" />;
}
