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
