// Self-update. Runs ONLY inside the Tauri shell — in browser/mock mode this is a no-op
// so the dev/demo/screenshot experience is untouched (mirrors the guard in
// src/bridge/index.ts). The updater plugin fetches the release manifest, verifies its
// signature against the pubkey in tauri.conf.json, downloads the matching artifact, and
// installs it; the process plugin relaunches into the new version.

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export interface UpdateStatus {
  state: "idle" | "checking" | "downloading" | "up-to-date" | "ready" | "error";
  version?: string;
  message?: string;
}

/**
 * Check for an update. When `autoInstall` is true (the on-launch path), a found update
 * is downloaded, installed, and the app relaunches. When false (the Settings button),
 * it just reports whether one is available so the UI can prompt.
 */
export async function checkForUpdate(
  onStatus?: (s: UpdateStatus) => void,
  autoInstall = true,
): Promise<UpdateStatus> {
  if (!inTauri()) {
    const s: UpdateStatus = { state: "idle", message: "updates apply to the installed app only" };
    onStatus?.(s);
    return s;
  }
  try {
    onStatus?.({ state: "checking" });
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (!update) {
      const s: UpdateStatus = { state: "up-to-date" };
      onStatus?.(s);
      return s;
    }
    if (!autoInstall) {
      const s: UpdateStatus = { state: "ready", version: update.version };
      onStatus?.(s);
      return s;
    }
    onStatus?.({ state: "downloading", version: update.version });
    await update.downloadAndInstall();
    const { relaunch } = await import("@tauri-apps/plugin-process");
    await relaunch();
    // Unreachable after relaunch, but return a sensible value for callers.
    return { state: "ready", version: update.version };
  } catch (e) {
    const s: UpdateStatus = { state: "error", message: String(e) };
    onStatus?.(s);
    return s;
  }
}
