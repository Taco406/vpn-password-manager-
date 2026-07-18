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
