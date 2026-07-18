// MV3 service worker. Bridges popup/content messages to the desktop app over a native
// messaging port. It caches ONLY the lock state and the VPN status pill — never any
// credential data. While the desktop is locked, every vault request resolves to a
// LOCKED error and no secret ever crosses this worker.

import { NM_HOST_NAME, type NmEnvelope } from "./protocol";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime = (globalThis as any).chrome?.runtime;

interface Pending {
  resolve: (env: NmEnvelope) => void;
  reject: (e: Error) => void;
}

let port: chrome.runtime.Port | null = null;
const pending = new Map<string, Pending>();
let status = { locked: true, vpn: { stage: "idle", region: undefined as string | undefined, rx: 0, tx: 0 } };
let seq = 0;

function connect(): chrome.runtime.Port | null {
  if (port) return port;
  try {
    port = runtime.connectNative(NM_HOST_NAME);
    port!.onMessage.addListener((msg: NmEnvelope) => {
      if (msg.type === "status.event") {
        // Cache only non-secret status.
        const p = msg.payload as { locked: boolean; vpn: typeof status.vpn };
        status = { locked: p.locked, vpn: p.vpn };
        return;
      }
      const waiter = pending.get(msg.id);
      if (waiter) {
        pending.delete(msg.id);
        waiter.resolve(msg);
      }
    });
    port!.onDisconnect.addListener(() => {
      port = null;
      status.locked = true;
      for (const [, w] of pending) w.reject(new Error("host disconnected"));
      pending.clear();
    });
    // Handshake.
    void send("hello", {});
  } catch {
    port = null;
  }
  return port;
}

function send(type: string, payload: unknown): Promise<NmEnvelope> {
  const p = connect();
  const id = `bg-${++seq}`;
  if (!p) {
    // No desktop: behave as locked, never invent data.
    return Promise.resolve({ id, type: "lock.event", ok: false, err: { code: "LOCKED", message: "desktop not running" } } as NmEnvelope);
  }
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    p.postMessage({ id, type, payload });
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error("timeout"));
      }
    }, 5000);
  });
}

// Popup / content-script RPC.
runtime?.onMessage?.addListener((req: { cmd: string; payload?: unknown }, _sender: unknown, sendResponse: (r: unknown) => void) => {
  (async () => {
    switch (req.cmd) {
      case "status":
        sendResponse(status);
        break;
      case "search":
      case "fields":
      case "totp":
      case "generate":
      case "save_candidate": {
        const map: Record<string, string> = {
          search: "vault.search",
          fields: "vault.fields.get",
          totp: "vault.totp.get",
          generate: "vault.generate",
          save_candidate: "vault.save_candidate",
        };
        const reply = await send(map[req.cmd], req.payload);
        sendResponse(reply);
        break;
      }
      default:
        sendResponse({ error: "unknown command" });
    }
  })();
  return true; // async response
});

export {}; // module
