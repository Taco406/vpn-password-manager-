// Shared live state: lock status, VPN connect state + metrics, clipboard countdown,
// and theme. Subscribes to bridge events once.

import { create } from "zustand";
import type { ConnectState, Settings, VpnMetrics } from "@sentinel/shared";
import { bridge, lockStatus } from "../bridge";

const MAX_SAMPLES = 90;

interface AppState {
  locked: boolean;
  connect: ConnectState;
  metrics: VpnMetrics | null;
  rxHistory: number[];
  txHistory: number[];
  clipboard: { field: string; remainingMs: number } | null;
  theme: "dark" | "light" | "system";
  settings: Settings | null;
  setLocked: (v: boolean) => void;
  setTheme: (t: "dark" | "light" | "system") => void;
  refreshSettings: () => Promise<void>;
  init: () => void;
}

export const useApp = create<AppState>((set, get) => ({
  // Unlocked by default (personal-use tool). On launch we ask the backend whether the user has
  // opted into a lock (master password / authenticator / Windows Hello) and lock only if so.
  locked: false,
  connect: { stage: "idle" },
  metrics: null,
  rxHistory: [],
  txHistory: [],
  clipboard: null,
  theme: "dark",
  settings: null,

  setLocked: (v) => set({ locked: v }),
  setTheme: (t) => {
    set({ theme: t });
    const resolved =
      t === "system"
        ? window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark"
        : t;
    document.documentElement.setAttribute("data-theme", resolved);
    void bridge.settingsSet({ theme: t });
  },
  refreshSettings: async () => {
    const s = await bridge.settingsGet();
    set({ settings: s, theme: s.theme });
  },

  init: () => {
    if ((get() as unknown as { _subscribed?: boolean })._subscribed) return;
    set({ _subscribed: true } as Partial<AppState>);
    // Reflect the real backend lock state: locked only if the user opted into protection.
    void lockStatus()
      .then((s) => set({ locked: s.locked }))
      .catch(() => {});
    bridge.on((e) => {
      switch (e.type) {
        case "vpn:state":
          set({ connect: e.state });
          if (e.state.stage === "idle") set({ rxHistory: [], txHistory: [], metrics: null });
          break;
        case "vpn:metrics": {
          const { rxHistory, txHistory } = get();
          set({
            metrics: e.metrics,
            rxHistory: [...rxHistory, e.metrics.rx].slice(-MAX_SAMPLES),
            txHistory: [...txHistory, e.metrics.tx].slice(-MAX_SAMPLES),
          });
          break;
        }
        case "clipboard:countdown":
          set({
            clipboard: e.remainingMs > 0 ? { field: e.field, remainingMs: e.remainingMs } : null,
          });
          break;
        case "vault:locked":
          set({ locked: true });
          break;
      }
    });
  },
}));
