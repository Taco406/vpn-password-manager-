// Idle auto-lock. Settings has offered an "Auto-lock after N minutes" slider since the first
// release, but nothing ever consumed it — the value was written to settings.json and read back
// by nobody, so the vault stayed unlocked indefinitely. This makes the setting real.
//
// The timer only matters when the user has actually opted into protection (a master password);
// with no password there is nothing to lock back to, and locking would just be a dead end.

import { useEffect, useRef } from "react";
import { bridge, lockStatus } from "../bridge";

/** Activity that counts as "the user is still here". */
const ACTIVITY_EVENTS = ["mousedown", "keydown", "wheel", "touchstart", "mousemove"] as const;

/**
 * Locks the vault after `minutes` of no interaction. A no-op when the vault has no master
 * password (nothing to re-unlock with) or when `minutes` is unset.
 */
export function useAutoLock(minutes: number | undefined) {
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!minutes || minutes <= 0) return;
    let cancelled = false;
    let armed = false;

    const clear = () => {
      if (timer.current !== undefined) window.clearTimeout(timer.current);
      timer.current = undefined;
    };

    const arm = () => {
      clear();
      timer.current = window.setTimeout(
        () => {
          void bridge.lock();
        },
        minutes * 60 * 1000,
      );
    };

    const onActivity = () => {
      if (armed) arm();
    };

    // Only arm once we know a master password exists — otherwise `lock()` would strand the
    // user on an unlock screen they can't pass.
    void lockStatus()
      .then((s) => {
        if (cancelled || !s.passwordProtected) return;
        armed = true;
        arm();
        ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
      })
      .catch(() => {
        /* not in the desktop shell — no auto-lock */
      });

    return () => {
      cancelled = true;
      clear();
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, onActivity));
    };
  }, [minutes]);
}
