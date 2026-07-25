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

// --- Install-attempt marker (the loop breaker) -------------------------------
// The Windows installer runs AFTER this process exits, so a failed apply is invisible to the
// app that started it: the user reopens, the app is still the old version, sees the same
// update, and the cycle repeats. Persisting {from, to} lets the next launch detect "we tried
// to reach X but we're still on Y" and say so once, plainly, instead of looping.

const ATTEMPT_KEY = "nk-update-attempt";

export function markInstallAttempt(from: string, to: string): void {
  try {
    localStorage.setItem(ATTEMPT_KEY, JSON.stringify({ from, to, ts: Date.now() }));
  } catch {
    /* storage unavailable — worst case we just lose the loop-breaker, not the update */
  }
}

/**
 * How the LAST install attempt ended. Returns the target version when it demonstrably did
 * NOT apply (we're still on the version we started from); null when it applied, there was
 * no attempt, or the marker is stale (>7 days).
 */
export async function failedInstallAttempt(): Promise<string | null> {
  if (!inTauri()) return null;
  try {
    const raw = localStorage.getItem(ATTEMPT_KEY);
    if (!raw) return null;
    const m = JSON.parse(raw) as { from?: string; to?: string; ts?: number };
    const app = await import("@tauri-apps/api/app");
    const current = await app.getVersion();
    if (!m.to || m.to === current || !m.ts || Date.now() - m.ts > 7 * 24 * 3_600_000) {
      localStorage.removeItem(ATTEMPT_KEY); // applied, malformed, or stale
      return null;
    }
    if (m.from === current) return m.to; // installer ran but nothing changed
    localStorage.removeItem(ATTEMPT_KEY);
    return null;
  } catch {
    return null;
  }
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
    // Record the attempt BEFORE installing. On Windows the installer runs after this app
    // exits, so a failed apply is invisible to this process — the marker lets the NEXT launch
    // notice "we tried to reach X but we're still on Y" and say so, instead of the app
    // silently looping through the same doomed install forever.
    {
      const app = await import("@tauri-apps/api/app");
      markInstallAttempt(await app.getVersion(), update.version);
    }
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
