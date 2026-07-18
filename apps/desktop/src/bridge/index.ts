// Bridge selection: the real Tauri bridge inside the shell, the deterministic mock in the
// browser / demo / screenshots. Resolved synchronously at module load so every consumer
// holds the correct implementation (an earlier version captured the mock and never swapped).

import type { SentinelBridge } from "@sentinel/shared";
import { mockBridge } from "./mock";
import { createTauriBridge } from "./tauri";

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// createTauriBridge() is import-safe in the browser (it lazy-imports @tauri-apps/api only
// when a method is actually called), so constructing it eagerly here is fine; we just never
// do so outside the Tauri shell.
export const bridge: SentinelBridge = inTauri() ? createTauriBridge() : mockBridge;

export function getBridge(): SentinelBridge {
  return bridge;
}

// --- Real-VPN (Linode) opt-in helpers ---------------------------------------
// Not part of the SentinelBridge contract (they only mean something in the shell). In the
// browser they no-op / report disabled, so Settings works in both modes.

export async function vpnSetToken(token: string): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("vpn_set_token", { token });
}

export async function vpnRealEnabled(): Promise<boolean> {
  if (!inTauri()) return false;
  const core = await import("@tauri-apps/api/core");
  const c = (await core.invoke("vpn_config")) as { realEnabled?: boolean };
  return !!c?.realEnabled;
}
