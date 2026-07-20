// Bridge selection: the real Tauri bridge inside the shell, the deterministic mock in the
// browser / demo / screenshots. Resolved synchronously at module load so every consumer
// holds the correct implementation (an earlier version captured the mock and never swapped).

import type { SentinelBridge, AuditReport } from "@sentinel/shared";
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

// --- VPN depth (experimental, real-VPN only): kill switch + untrusted-Wi-Fi auto-connect ---
// Not part of the SentinelBridge contract (they only mean something in the shell, and only in
// real-Linode mode). In the browser they no-op / return safe defaults so Settings renders.

export interface NetStatusInfo {
  ssid: string | null;
  trusted: boolean;
  autoConnect: boolean;
}

/** Current Wi-Fi SSID + whether it's trusted, and whether untrusted-Wi-Fi auto-connect is on. */
export async function netStatus(): Promise<NetStatusInfo> {
  if (!inTauri()) return { ssid: null, trusted: false, autoConnect: false };
  const core = await import("@tauri-apps/api/core");
  const s = (await core.invoke("net_status")) as {
    ssid?: string | null;
    trusted?: boolean;
    autoConnect?: boolean;
  };
  return {
    ssid: s?.ssid ?? null,
    trusted: !!s?.trusted,
    autoConnect: !!s?.autoConnect,
  };
}

/** Persist the auto-connect toggle and the trusted-SSID allowlist. */
export async function netSet(autoConnect: boolean, trustedSsids: string[]): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("net_set", { autoConnect, trustedSsids });
}

/** Manual panic button: remove every kill-switch firewall rule immediately. */
export async function killswitchClear(): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("killswitch_clear");
}

// --- VPN node lifecycle (experimental, real-VPN only): keep vs destroy + manage the fleet ---

export interface VpnNode {
  id: string;
  region: string;
  instanceType: string;
  state: string; // running | booting | provisioning | stopped | deleting | gone
  kept: boolean;
  current: boolean;
  hourlyUsd: number;
}

export interface VpnCostSummary {
  nodeCount: number;
  running: number;
  stopped: number;
  hourlyUsd: number;
}

/** List every SENTINEL exit node on the account, with live state + whether it's kept/current. */
export async function vpnNodes(): Promise<VpnNode[]> {
  if (!inTauri()) return [];
  const core = await import("@tauri-apps/api/core");
  return core.invoke("vpn_nodes") as Promise<VpnNode[]>;
}

/** Running cost across all existing nodes (running + stopped both bill on Linode). */
export async function vpnCostSummary(): Promise<VpnCostSummary> {
  if (!inTauri()) return { nodeCount: 0, running: 0, stopped: 0, hourlyUsd: 0 };
  const core = await import("@tauri-apps/api/core");
  return core.invoke("vpn_cost_summary") as Promise<VpnCostSummary>;
}

/** Disconnect but KEEP the node (power it off instead of destroying it). Still bills until destroyed. */
export async function vpnDisconnectKeep(): Promise<void> {
  if (!inTauri()) throw new Error("Real VPN is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("vpn_disconnect_keep");
}

/** Power a node start | stop | reboot, or delete it. */
export async function vpnNodeAction(
  id: string,
  action: "start" | "stop" | "reboot" | "delete",
): Promise<void> {
  if (!inTauri()) throw new Error("Real VPN is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("vpn_node_action", { id, action });
}

/** Panic button: destroy every node and stop all billing. Returns how many were destroyed. */
export async function vpnNodesDestroyAll(): Promise<number> {
  if (!inTauri()) return 0;
  const core = await import("@tauri-apps/api/core");
  return core.invoke("vpn_nodes_destroy_all") as Promise<number>;
}

/**
 * Connect through a CHAIN of exit nodes (multi-hop "bounce"). `regions` is entry→exit (2–3).
 * Cost is N× a single node. Experimental; real-VPN (Linode) only.
 */
export async function vpnConnectMultihop(regions: string[], instanceType?: string): Promise<void> {
  if (!inTauri()) throw new Error("Real VPN is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("vpn_connect_multihop", { regions, instanceType: instanceType ?? null });
}

// --- Browser autofill (experimental) opt-in helpers -------------------------
// Register/unregister this app as the Chrome/Edge native-messaging host. Not part of the
// SentinelBridge contract (they only mean something in the shell); in the browser they
// no-op / report disabled so Settings renders in both modes.

export async function autofillStatus(): Promise<{ installed: boolean }> {
  if (!inTauri()) return { installed: false };
  const core = await import("@tauri-apps/api/core");
  return core.invoke("autofill_status") as Promise<{ installed: boolean }>;
}

export async function autofillInstall(): Promise<void> {
  if (!inTauri()) throw new Error("Browser autofill is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("autofill_install");
}

export async function autofillUninstall(): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("autofill_uninstall");
}

/** Copy the bundled extension to a stable folder and return its path (for "Load unpacked"). */
export async function autofillPrepare(): Promise<string> {
  if (!inTauri()) throw new Error("Browser autofill is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  return core.invoke("autofill_prepare") as Promise<string>;
}

/** Reveal a folder in the OS file manager. */
export async function openFolder(path: string): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("open_folder", { path });
}

// --- Network tools (Tools screen): what's-my-IP + geo, TCP ping, DNS ---------
// Go out the app's current route, so with the VPN connected they reflect the exit node.

export interface MyIp {
  ip: string;
  city: string;
  region: string;
  country: string;
  org: string;
  lat: number | null;
  lon: number | null;
}

/** Public IP + coarse geolocation as seen from this device now (reflects the VPN exit if on). */
export async function netMyIp(): Promise<MyIp> {
  if (!inTauri()) throw new Error("Network tools are only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  return core.invoke("net_myip") as Promise<MyIp>;
}

export interface PingResult {
  host: string;
  ip: string;
  port: number;
  ms: number;
  attempts: number;
}

/** TCP-connect latency probe to a host (443, then 80). Best of a few attempts, in ms. */
export async function netPing(host: string): Promise<PingResult> {
  if (!inTauri()) throw new Error("Network tools are only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  return core.invoke("net_ping", { host }) as Promise<PingResult>;
}

/** Resolve a hostname to its IP addresses. */
export async function netDns(host: string): Promise<string[]> {
  if (!inTauri()) throw new Error("Network tools are only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  return core.invoke("net_dns", { host }) as Promise<string[]>;
}

/**
 * Instant local vault audit (reused / weak / old, no network) so the Health tab renders without
 * waiting on the HIBP breach check. The full `bridge.healthAudit()` runs after and fills breaches.
 * In the browser demo the mock audit is already instant, so we just use it.
 */
export async function healthAuditFast(): Promise<AuditReport> {
  if (!inTauri()) return bridge.healthAudit();
  const core = await import("@tauri-apps/api/core");
  return core.invoke("health_audit_fast") as Promise<AuditReport>;
}

// --- App lock: opt-in master password + authenticator-app (TOTP) unlock -----
// The app is unlocked by default; these engage only once the user turns them on. Standalone
// (not part of the SentinelBridge contract) — no-op / safe defaults in the browser demo.

export interface AppLockStatus {
  locked: boolean;
  passwordProtected: boolean;
  totpEnabled: boolean;
  requireHello: boolean;
}

/** Current app-lock state (used to decide whether to show the Unlock screen). */
export async function lockStatus(): Promise<AppLockStatus> {
  const fallback: AppLockStatus = {
    locked: false,
    passwordProtected: false,
    totpEnabled: false,
    requireHello: false,
  };
  if (!inTauri()) return fallback;
  const core = await import("@tauri-apps/api/core");
  const s = (await core.invoke("auth_status")) as Partial<AppLockStatus>;
  return { ...fallback, ...s };
}

/** Set a master password (wraps the vault key; the app now locks on launch). */
export async function lockSetPassword(password: string): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("auth_set_password", { password });
}

/** Unlock the vault with the master password (+ authenticator code if enabled). */
export async function lockUnlockPassword(password: string, code?: string): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("auth_unlock_password", { password, code: code ?? null });
}

export async function lockChangePassword(
  oldPassword: string,
  newPassword: string,
  code?: string,
): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("auth_change_password", {
    oldPassword,
    newPassword,
    code: code ?? null,
  });
}

/** Remove the master password (back to unlocked-by-default). */
export async function lockRemovePassword(password: string, code?: string): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("auth_remove_password", { password, code: code ?? null });
}

export interface LockTotpEnroll {
  otpauthUri: string;
  secret: string;
  qrSvg: string;
}

/** Begin authenticator-app enrollment — returns the QR (SVG) + typed secret. */
export async function lockTotpEnroll(): Promise<LockTotpEnroll> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  return core.invoke("applock_totp_enroll") as Promise<LockTotpEnroll>;
}

/** Confirm authenticator enrollment with a code, enabling the 2-step unlock. */
export async function lockTotpConfirm(code: string): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("applock_totp_confirm", { code });
}

/** Turn off the authenticator-app requirement (verify a current code first). */
export async function lockTotpDisable(code: string): Promise<void> {
  if (!inTauri()) throw new Error("Only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("applock_totp_disable", { code });
}

// --- WireGuard prerequisite monitor (real-VPN) ------------------------------

export interface WgStatusInfo {
  installed: boolean;
  path: string | null;
  elevated: boolean;
  elevationMatters: boolean;
  downloadUrl: string;
}

/** Whether WireGuard is installed locally and whether SENTINEL is elevated (both needed to connect). */
export async function wgStatus(): Promise<WgStatusInfo> {
  const fallback: WgStatusInfo = {
    installed: false,
    path: null,
    elevated: false,
    elevationMatters: false,
    downloadUrl: "https://www.wireguard.com/install/",
  };
  if (!inTauri()) return fallback;
  const core = await import("@tauri-apps/api/core");
  const s = (await core.invoke("wg_status")) as Partial<WgStatusInfo>;
  return { ...fallback, ...s };
}

/**
 * Emergency recovery: remove any leftover SENTINEL WireGuard tunnel and clear kill-switch rules,
 * to restore internet if a failed connect left routing captured. Safe no-op if nothing is stuck.
 */
// --- Always-on (persistent) VPN node ---------------------------------------

export interface PersistentVpnStatus {
  deployed: boolean;
  ipv4?: string;
  region?: string;
  state?: string;
  connected: boolean;
  hourlyUsd: number;
  monthlyUsd: number;
}

export async function vpnPersistentStatus(): Promise<PersistentVpnStatus> {
  if (!inTauri()) return { deployed: false, connected: false, hourlyUsd: 0, monthlyUsd: 0 };
  return inv<PersistentVpnStatus>("vpn_persistent_status");
}

/** Provision a durable always-on VPN node and connect to it. Long-running. */
export async function vpnPersistentDeploy(region: string, instanceType: string): Promise<void> {
  if (!inTauri()) throw new Error("The always-on VPN is only available in the desktop app.");
  await inv("vpn_persistent_deploy", { region, instanceType });
}

/** Connect (or reconnect) to the already-deployed always-on node. */
export async function vpnPersistentConnect(): Promise<void> {
  if (!inTauri()) throw new Error("The always-on VPN is only available in the desktop app.");
  await inv("vpn_persistent_connect");
}

/** Destroy the always-on node (stops billing) and clear its local record. */
export async function vpnPersistentDestroy(): Promise<void> {
  if (!inTauri()) return;
  await inv("vpn_persistent_destroy");
}

/** Subscribe to always-on deploy progress; returns an unsubscribe fn. */
export async function onVpnPersistent(
  cb: (e: { stage: string; detail: string }) => void,
): Promise<() => void> {
  if (!inTauri()) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<{ stage: string; detail: string }>("vpn:persistent", (ev) => cb(ev.payload));
}

export async function vpnRepairTunnel(): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("vpn_repair_tunnel");
}

/** Open an http(s) URL in the default browser. */
export async function openUrl(url: string): Promise<void> {
  if (!inTauri()) {
    window.open?.(url, "_blank", "noopener");
    return;
  }
  const core = await import("@tauri-apps/api/core");
  await core.invoke("open_url", { url });
}

// --- Diagnostics error log --------------------------------------------------

/** The last `limit` lines of the app's diagnostics log (errors + notable events). */
export async function logTail(limit = 200): Promise<string> {
  if (!inTauri()) return "";
  const core = await import("@tauri-apps/api/core");
  return core.invoke("log_tail", { limit }) as Promise<string>;
}

/** Clear the diagnostics log. */
export async function logClear(): Promise<void> {
  if (!inTauri()) return;
  const core = await import("@tauri-apps/api/core");
  await core.invoke("log_clear");
}

/** The folder holding the log file (for an "Open folder" button). */
export async function logDirPath(): Promise<string> {
  if (!inTauri()) return "";
  const core = await import("@tauri-apps/api/core");
  return core.invoke("log_dir_path") as Promise<string>;
}

// --- Windows Hello unlock opt-in helpers ------------------------------------

export async function helloStatus(): Promise<{ available: boolean; enabled: boolean }> {
  if (!inTauri()) return { available: false, enabled: false };
  const core = await import("@tauri-apps/api/core");
  return core.invoke("hello_status") as Promise<{ available: boolean; enabled: boolean }>;
}

export async function helloSet(enabled: boolean): Promise<void> {
  if (!inTauri()) throw new Error("Windows Hello is only available in the desktop app.");
  const core = await import("@tauri-apps/api/core");
  await core.invoke("hello_set", { enabled });
}

// --- Account & Sync (Stage 3) opt-in helpers --------------------------------
// Not part of the SentinelBridge contract (they only mean something in the shell). In the
// browser they no-op / return defaults so Settings renders in both modes.

export interface SyncStatusInfo {
  serverUrl: string | null;
  googleClientId: string | null;
  signedIn: boolean;
  email: string | null;
}

export interface SyncDevice {
  id: string;
  name: string;
  platform: string;
  status: string;
  createdAt: string;
  current: boolean;
}

async function inv<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const core = await import("@tauri-apps/api/core");
  return core.invoke(cmd, args) as Promise<T>;
}

// --- One-click "Deploy my sync server" (durable Linode, reuses the VPN's Linode token) ------

export interface SyncServerStatus {
  deployed: boolean;
  ipv4?: string;
  state?: string;
  hourlyUsd: number;
  monthlyUsd: number;
}

export async function syncServerStatus(): Promise<SyncServerStatus> {
  if (!inTauri()) return { deployed: false, hourlyUsd: 0, monthlyUsd: 0 };
  return inv<SyncServerStatus>("sync_server_status");
}

/**
 * Provision a durable Linode running the sync server and auto-configure the app. Long-running.
 * Pass a Google OAuth client id to deploy a Google-sign-in server (this device then finishes via
 * the Google + TOTP flow); omit it for the personal bootstrap server that signs in automatically.
 */
export async function syncDeploy(
  region: string,
  instanceType?: string,
  googleClientId?: string,
): Promise<void> {
  if (!inTauri()) throw new Error("Deploying a sync server is only available in the desktop app.");
  await inv("sync_deploy", {
    region,
    instanceType: instanceType ?? null,
    googleClientId: googleClientId?.trim() ? googleClientId.trim() : null,
  });
}

/** Destroy the deployed sync server (stops billing) and clear local sync state. */
export async function syncServerDestroy(): Promise<void> {
  if (!inTauri()) return;
  await inv("sync_server_destroy");
}

/** Subscribe to deploy progress events; returns an unsubscribe fn. */
export async function onSyncDeploy(
  cb: (e: { stage: string; detail: string }) => void,
): Promise<() => void> {
  if (!inTauri()) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<{ stage: string; detail: string }>("sync:deploy", (ev) => cb(ev.payload));
}

export async function syncStatus(): Promise<SyncStatusInfo> {
  if (!inTauri()) return { serverUrl: null, googleClientId: null, signedIn: false, email: null };
  return inv<SyncStatusInfo>("sync_status");
}

export async function syncSetConfig(
  serverUrl: string | null,
  googleClientId: string | null,
): Promise<void> {
  if (!inTauri()) return;
  await inv("sync_set_config", { serverUrl, googleClientId });
}

export async function authGoogleSignin(): Promise<{ email: string; totpRequired: boolean }> {
  if (!inTauri()) throw new Error("Sign-in is only available in the desktop app.");
  return inv<{ email: string; totpRequired: boolean }>("auth_google_signin");
}

export async function authTotpEnroll(): Promise<{ otpauthUri: string; secret: string }> {
  if (!inTauri()) throw new Error("Sign-in is only available in the desktop app.");
  return inv<{ otpauthUri: string; secret: string }>("auth_totp_enroll");
}

export async function authTotpVerify(code: string): Promise<void> {
  if (!inTauri()) throw new Error("Sign-in is only available in the desktop app.");
  await inv("auth_totp_verify", { code });
}

export async function authLogout(): Promise<void> {
  if (!inTauri()) return;
  await inv("auth_logout");
}

export async function syncBackup(): Promise<{
  recoveryCode: string;
  pdfBase64: string;
  version: number;
}> {
  if (!inTauri()) throw new Error("Backup is only available in the desktop app.");
  return inv<{ recoveryCode: string; pdfBase64: string; version: number }>("sync_backup");
}

export async function syncNow(): Promise<{ pushed: boolean; pulled: boolean; version: number }> {
  if (!inTauri()) throw new Error("Sync is only available in the desktop app.");
  return inv<{ pushed: boolean; pulled: boolean; version: number }>("sync_now");
}

export async function syncRestore(code: string): Promise<{ restored: number }> {
  if (!inTauri()) throw new Error("Restore is only available in the desktop app.");
  return inv<{ restored: number }>("sync_restore", { recoveryCode: code });
}

export async function syncDevices(): Promise<SyncDevice[]> {
  if (!inTauri()) return [];
  return inv<SyncDevice[]>("sync_devices");
}

export async function syncDeviceRevoke(id: string): Promise<void> {
  if (!inTauri()) return;
  await inv("sync_device_revoke", { id });
}

/**
 * Finish (or repair) sign-in to an already-deployed one-click sync server whose initial
 * sign-in didn't complete (e.g. the server was still installing when the deploy timed out).
 * No destroy/redeploy — reuses the saved server address, pinned cert, and bootstrap token.
 */
export async function syncReconnect(): Promise<{ signedIn: boolean }> {
  if (!inTauri()) throw new Error("Reconnecting is only available in the desktop app.");
  return inv<{ signedIn: boolean }>("sync_reconnect");
}

/** Mint a one-shot device-join code so another computer can join this device's sync server. */
export async function syncPairBegin(): Promise<{ code: string; createdAt: string }> {
  if (!inTauri()) throw new Error("Device pairing is only available in the desktop app.");
  return inv<{ code: string; createdAt: string }>("sync_pair_begin");
}

/** Join the sync server described by a device-join code from another computer (empty vault only). */
export async function syncPairComplete(code: string): Promise<{ restored: number; serverIp: string }> {
  if (!inTauri()) throw new Error("Device pairing is only available in the desktop app.");
  return inv<{ restored: number; serverIp: string }>("sync_pair_complete", { code });
}

/**
 * Forget the sync server this device points at (clears config + tokens, keeps the local vault and
 * any deployed Linode). Escape hatch for a device stuck on a server that's gone away or was wrong.
 */
export async function syncForget(): Promise<void> {
  if (!inTauri()) return;
  await inv("sync_forget");
}
