// The real Tauri bridge. Vault, generator, health, settings, and lock/unlock are served
// by the Rust backend via `invoke` (persistent, keychain-unlocked). VPN, auth, devices,
// pairing, import/export and favicons are still served by the deterministic in-browser
// simulation (delegated to `mockBridge`) — those become real in a later stage.

import type {
  AuditReport,
  AuthState,
  BridgeEvent,
  ConnectState,
  ConnectionProfile,
  DeviceInfo,
  GeneratedPassword,
  ImportKind,
  InstanceType,
  ItemDetail,
  ItemInput,
  ItemSummary,
  KeyringStatus,
  PassphraseSpec,
  PasswordSpec,
  Region,
  ReportData,
  SentinelBridge,
  SessionRow,
  Settings,
  Unsubscribe,
  WrapperEnrollResult,
} from "@sentinel/shared";
import { mockBridge } from "./mock";

// Lazily resolve the Tauri APIs so this module is import-safe in the browser (the browser
// build never constructs this bridge; see bridge/index.ts).
async function api(): Promise<{
  invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
  listen: (e: string, cb: (p: unknown) => void) => Promise<() => void>;
}> {
  const core = await import("@tauri-apps/api/core");
  const event = await import("@tauri-apps/api/event");
  return {
    invoke: core.invoke as (cmd: string, args?: Record<string, unknown>) => Promise<unknown>,
    listen: (e, cb) =>
      event.listen(e, (ev) => cb((ev as { payload: unknown }).payload)) as Promise<() => void>,
  };
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke: inv } = await api();
  return inv(cmd, args) as Promise<T>;
}

export function createTauriBridge(): SentinelBridge {
  // Frontend-generated events (clipboard auto-clear countdown) are pushed to these.
  const localListeners = new Set<(e: BridgeEvent) => void>();
  const emitLocal = (e: BridgeEvent) => localListeners.forEach((l) => l(e));

  return {
    // --- keyring / unlock (real) ---
    keyringStatus: () => invoke<KeyringStatus>("keyring_status"),
    lock: () => invoke<void>("lock"),
    unlockPlatform: () => invoke<void>("unlock_platform"),
    unlockPhoneBegin: () => invoke<{ requestId: string }>("unlock_phone_begin"),
    unlockPhoneAwait: (requestId: string) => invoke<void>("unlock_phone_await", { requestId }),
    unlockRecovery: (key: string) => invoke<void>("unlock_recovery", { key }),

    // --- vault (real) ---
    vaultList: () => invoke<ItemSummary[]>("vault_list"),
    vaultGet: (id: string) => invoke<ItemDetail>("vault_get", { id }),
    vaultRevealField: (id: string, field: string) =>
      invoke<string>("vault_reveal_field", { id, field }),
    vaultSave: (item: ItemInput) => invoke<string>("vault_save", { item }),
    vaultDelete: (id: string) => invoke<void>("vault_delete", { id }),
    vaultTotp: (id: string) => invoke<{ code: string; remainingMs: number }>("vault_totp", { id }),
    generatorPassword: (spec: PasswordSpec) =>
      invoke<GeneratedPassword>("generator_password", { spec }),
    generatorPassphrase: (spec: PassphraseSpec) =>
      invoke<GeneratedPassword>("generator_passphrase", { spec }),
    healthAudit: () => invoke<AuditReport>("health_audit"),
    settingsGet: () => invoke<Settings>("settings_get"),
    settingsSet: (settings: Partial<Settings>) => invoke<void>("settings_set", { patch: settings }),

    // Copy the real revealed value to the OS clipboard, then run a visible auto-clear
    // countdown and wipe it — all in the webview, which has clipboard access.
    vaultCopyField: async (id: string, field: string) => {
      const value = await invoke<string>("vault_reveal_field", { id, field });
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        /* clipboard may be unavailable; countdown still runs */
      }
      const settings = await invoke<Settings>("settings_get").catch(
        () => ({ clipboardClearSeconds: 30 }) as Settings,
      );
      let remaining = (settings.clipboardClearSeconds ?? 30) * 1000;
      emitLocal({ type: "clipboard:countdown", remainingMs: remaining, field });
      const timer = setInterval(() => {
        remaining -= 1000;
        emitLocal({ type: "clipboard:countdown", remainingMs: Math.max(0, remaining), field });
        if (remaining <= 0) {
          clearInterval(timer);
          void navigator.clipboard.writeText("").catch(() => {});
        }
      }, 1000);
    },

    // --- delegated to the in-browser simulation (become real later) ---
    authStatus: (): Promise<AuthState> => mockBridge.authStatus(),
    authStartGoogle: () => mockBridge.authStartGoogle(),
    authTotpEnroll: () => mockBridge.authTotpEnroll(),
    authTotpVerify: (code: string) => mockBridge.authTotpVerify(code),
    useLocalOnly: () => mockBridge.useLocalOnly(),
    syncNow: () => mockBridge.syncNow(),
    logout: () => mockBridge.logout(),
    enrollWrapper: (t: "platform" | "phone" | "recovery"): Promise<WrapperEnrollResult> =>
      mockBridge.enrollWrapper(t),
    recoveryKitGenerate: () => mockBridge.recoveryKitGenerate(),
    recoveryKitVerify: (g: { index: number; value: string }[]) => mockBridge.recoveryKitVerify(g),
    vaultImport: (k: ImportKind, c: string) => mockBridge.vaultImport(k, c),
    vaultExport: (k: "encrypted" | "plain_csv", p?: string) => mockBridge.vaultExport(k, p),
    favicon: (d: string) => mockBridge.favicon(d),
    vpnRegions: (): Promise<Region[]> => mockBridge.vpnRegions(),
    vpnInstanceTypes: (): Promise<InstanceType[]> => mockBridge.vpnInstanceTypes(),
    vpnConnect: (r: string, i: string, p?: string) => mockBridge.vpnConnect(r, i, p),
    vpnDisconnect: () => mockBridge.vpnDisconnect(),
    vpnState: (): Promise<ConnectState> => mockBridge.vpnState(),
    vpnSpeedtest: () => mockBridge.vpnSpeedtest(),
    vpnHistory: (r: "week" | "month" | "all"): Promise<SessionRow[]> => mockBridge.vpnHistory(r),
    vpnCostEstimate: () => mockBridge.vpnCostEstimate(),
    vpnProfiles: (): Promise<ConnectionProfile[]> => mockBridge.vpnProfiles(),
    vpnProfileSave: (p: ConnectionProfile) => mockBridge.vpnProfileSave(p),
    reportMonth: (y: number, m: number): Promise<ReportData> => mockBridge.reportMonth(y, m),
    pairBegin: () => mockBridge.pairBegin(),
    pairAwait: (): Promise<DeviceInfo> => mockBridge.pairAwait(),
    devicesList: (): Promise<DeviceInfo[]> => mockBridge.devicesList(),
    deviceRevoke: (id: string) => mockBridge.deviceRevoke(id),

    // --- events: merge backend (vault:locked) + simulation (vpn/sync/pair) + local (clipboard) ---
    on: (handler: (e: BridgeEvent) => void): Unsubscribe => {
      localListeners.add(handler);
      const unsubMock = mockBridge.on((e) => {
        if (
          e.type === "vpn:state" ||
          e.type === "vpn:metrics" ||
          e.type === "sync:state" ||
          e.type === "pair:progress"
        ) {
          handler(e);
        }
      });
      const tauriUnsubs: Array<() => void> = [];
      void (async () => {
        const { listen } = await api();
        tauriUnsubs.push(
          await listen("vault:locked", () => handler({ type: "vault:locked" })),
        );
      })();
      return () => {
        localListeners.delete(handler);
        unsubMock();
        tauriUnsubs.forEach((u) => u());
      };
    },
  };
}
