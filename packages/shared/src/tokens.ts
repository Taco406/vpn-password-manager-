/**
 * SENTINEL design tokens — the single source of truth for the visual system
 * described in the brief. Dark-first, near-black blue-slate base, ONE electric-cyan
 * hero accent reserved for connection state / live data / primary CTAs, warm amber
 * for warnings. Consumed by Tailwind config and any inline canvas drawing (globe,
 * charts) so every surface reads as one system.
 */

export const color = {
  // Base — near-black blue-slate, layered by elevation.
  bg: {
    base: "#0A0E14",
    raised: "#0F141C",
    overlay: "#141B26",
    inset: "#080B10",
  },
  border: {
    subtle: "#1C2531",
    strong: "#28323F",
    focus: "#22D3EE",
  },
  text: {
    primary: "#E6EDF3",
    secondary: "#9AA7B4",
    muted: "#5C6672",
    inverse: "#0A0E14",
  },
  // Hero accent — electric cyan. Connection state, live data, primary CTAs only.
  accent: {
    DEFAULT: "#22D3EE",
    hover: "#38DEF6",
    dim: "#0E7490",
    glow: "rgba(34, 211, 238, 0.35)",
  },
  // Warm amber — warnings only.
  warn: {
    DEFAULT: "#F5A524",
    dim: "#8A5A0B",
  },
  danger: {
    DEFAULT: "#F4436C",
    dim: "#7A1230",
  },
  ok: {
    DEFAULT: "#2ED47A",
    dim: "#12603A",
  },
} as const;

/** Light theme overrides. Dark is default; light is fully supported per the brief. */
export const lightColor = {
  bg: {
    base: "#F5F7FA",
    raised: "#FFFFFF",
    overlay: "#FFFFFF",
    inset: "#ECEFF3",
  },
  border: {
    subtle: "#DCE2EA",
    strong: "#C3CCD7",
    focus: "#0E7490",
  },
  text: {
    primary: "#0A0E14",
    secondary: "#4A5561",
    muted: "#77828E",
    inverse: "#FFFFFF",
  },
  accent: {
    DEFAULT: "#0891B2",
    hover: "#06768F",
    dim: "#67E8F9",
    glow: "rgba(8, 145, 178, 0.25)",
  },
} as const;

export const font = {
  ui: '"Inter", "Geist", system-ui, -apple-system, sans-serif',
  mono: '"JetBrains Mono", "SF Mono", ui-monospace, monospace',
} as const;

export const radius = {
  sm: "6px",
  md: "10px",
  lg: "16px",
  xl: "24px",
  full: "9999px",
} as const;

/** Timing tuned so signature moments feel deliberate but never sluggish. */
export const motion = {
  fast: 0.12,
  base: 0.22,
  slow: 0.4,
  spring: { type: "spring", stiffness: 420, damping: 34 },
  connectPulseMs: 1800,
} as const;

export type ColorSystem = typeof color;
