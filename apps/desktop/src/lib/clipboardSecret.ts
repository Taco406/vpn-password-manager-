// Copying a secret to the clipboard, with the auto-clear the vault copy path already had.
//
// The vault's "copy password" button cleared the clipboard after N seconds, but every OTHER
// copy path (the Health screen's generated replacement passwords) wrote the secret with a bare
// navigator.clipboard.writeText and left it there forever. Same secret, same clipboard, no
// timer — so the protection depended on which button you pressed. Route all of them here.

import { bridge } from "../bridge";

/** Seconds to leave a secret on the clipboard when settings can't be read. */
const FALLBACK_CLEAR_SECONDS = 30;

/**
 * Copy a secret and clear the clipboard after the user's configured delay.
 *
 * The clear is best-effort by nature (another app can win the clipboard, and a closed window
 * cancels the timer) — it reduces the exposure window, it does not guarantee erasure. Returns
 * the number of seconds after which the clear was scheduled so callers can say so.
 */
export async function copySecret(value: string): Promise<number> {
  await navigator.clipboard.writeText(value);
  let seconds = FALLBACK_CLEAR_SECONDS;
  try {
    const s = await bridge.settingsGet();
    seconds = s.clipboardClearSeconds ?? FALLBACK_CLEAR_SECONDS;
  } catch {
    /* keep the fallback */
  }
  window.setTimeout(() => {
    // Only wipe if the clipboard still holds OUR secret — clobbering something the user
    // copied in the meantime would be worse than leaving it.
    void navigator.clipboard
      .readText()
      .then((current) => {
        if (current === value) return navigator.clipboard.writeText("");
      })
      .catch(() => {
        // No read permission: fall back to clearing unconditionally, since leaving a
        // password on the clipboard is the worse failure.
        void navigator.clipboard.writeText("").catch(() => {});
      });
  }, seconds * 1000);
  return seconds;
}
