// The real Tauri bridge: forwards each SentinelBridge method to a Rust command via
// `invoke`, and fans out backend events through `listen`. Used only when running
// inside the Tauri shell; browser/demo mode uses the mock.

import type { BridgeEvent, SentinelBridge, Unsubscribe } from "@sentinel/shared";

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

// Lazily resolve the Tauri APIs so this module is import-safe in the browser.
async function tauri(): Promise<{ invoke: Invoke; listen: (e: string, cb: (p: unknown) => void) => Promise<() => void> }> {
  const core = await import("@tauri-apps/api/core");
  const event = await import("@tauri-apps/api/event");
  return {
    invoke: core.invoke as Invoke,
    listen: (e, cb) => event.listen(e, (ev) => cb((ev as { payload: unknown }).payload)) as Promise<() => void>,
  };
}

// A thin proxy that maps camelCase method calls to snake_case Tauri commands.
export function createTauriBridge(): SentinelBridge {
  const call = async (cmd: string, args?: Record<string, unknown>) => {
    const { invoke } = await tauri();
    return invoke(cmd, args);
  };
  const snake = (s: string) => s.replace(/[A-Z]/g, (m) => "_" + m.toLowerCase());

  const handler: ProxyHandler<Record<string, unknown>> = {
    get(_t, prop: string) {
      if (prop === "on") {
        return (cb: (e: BridgeEvent) => void): Unsubscribe => {
          const unsubs: Array<() => void> = [];
          const events = [
            "vpn:state",
            "vpn:metrics",
            "clipboard:countdown",
            "vault:locked",
            "sync:state",
            "pair:progress",
          ];
          void (async () => {
            const { listen } = await tauri();
            for (const e of events) {
              unsubs.push(await listen(e, (payload) => cb({ type: e, ...(payload as object) } as BridgeEvent)));
            }
          })();
          return () => unsubs.forEach((u) => u());
        };
      }
      return (...args: unknown[]) => call(snake(prop), args[0] as Record<string, unknown>);
    },
  };
  return new Proxy({}, handler) as unknown as SentinelBridge;
}
