// Bridge selection: real Tauri bridge inside the shell, deterministic mock in the
// browser / demo / screenshots (D14).

import type { SentinelBridge } from "@sentinel/shared";
import { mockBridge } from "./mock";

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

let _bridge: SentinelBridge | null = null;

export function getBridge(): SentinelBridge {
  if (_bridge) return _bridge;
  if (inTauri()) {
    // Loaded lazily to keep @tauri-apps/api out of the browser bundle graph.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    _bridge = mockBridge; // replaced below when running under Tauri
    void import("./tauri").then((m) => {
      _bridge = m.createTauriBridge();
    });
  } else {
    _bridge = mockBridge;
  }
  return _bridge;
}

export const bridge = getBridge();
