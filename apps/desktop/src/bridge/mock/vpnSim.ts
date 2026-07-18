// Deterministic VPN traffic + metrics simulator. The throughput formula mirrors the
// Rust `wg::controller::throughput_rate` and `vpn::metrics::sample_at` byte-for-byte
// (a golden test compares samples), so the demo and the real backend agree.

export function throughputRate(t: number): number {
  const base = 6_000_000;
  const a = 3_500_000;
  const b = 1_800_000;
  const c = 2_200_000;
  return Math.max(0, base + a * Math.sin(t / 7) + b * Math.sin(t / 2.3) + c * Math.sin(t / 11));
}

export function cumulativeBytes(t: number): number {
  const base = 6_000_000;
  const terms: [number, number][] = [
    [3_500_000, 7],
    [1_800_000, 2.3],
    [2_200_000, 11],
  ];
  let total = base * t;
  for (const [k, p] of terms) total += k * p * (1 - Math.cos(t / p));
  return Math.max(0, total);
}

export interface MetricsSample {
  rx: number;
  tx: number;
  cpuPct: number;
  memPct: number;
  nicPct: number;
  latencyMs: number;
  t: number;
}

export function sampleAt(t: number): MetricsSample {
  const rx = throughputRate(t);
  const tx = rx / 6;
  const nicPct = Math.min(100, (rx / 118_000_000) * 100);
  const cpuPct = Math.max(0, Math.min(100, nicPct * 0.7 + 12 + 8 * Math.sin(t / 13)));
  const memPct = Math.max(0, Math.min(100, 28 + 5 * Math.sin(t / 40)));
  const latencyMs = 18 + 4 * Math.abs(Math.sin(t / 5));
  return { rx, tx, cpuPct, memPct, nicPct, latencyMs, t };
}

// Connect timeline (compressed): stage → cumulative ms at which it begins.
export const CONNECT_TIMELINE: { stage: string; atMs: number }[] = [
  { stage: "creatingInstance", atMs: 0 },
  { stage: "booting", atMs: 1500 },
  { stage: "exchangingKeys", atMs: 4500 },
  { stage: "startingTunnel", atMs: 5500 },
  { stage: "connected", atMs: 6300 },
];
