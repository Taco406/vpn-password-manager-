// In-app confirm dialog. Tauri v2's webview stubs out `window.confirm` — it returns
// undefined immediately and shows nothing — so EVERY confirm-guarded button silently
// did nothing: Install updates, permanent bans, promote-to-enforced, the power
// confirms, destroy-server. This is the working replacement: `askConfirm(message)`
// resolves true/false from a real in-app modal. Toast-style singleton (no context
// plumbing); one <ConfirmHost/> mounted in App.

import { useEffect, useState } from "react";
import { btnCls } from "./kit";

interface Ask {
  id: number;
  message: string;
  resolve: (ok: boolean) => void;
}

let listener: ((a: Ask) => void) | null = null;
let seq = 0;

/** Ask the user to confirm. Resolves false on Cancel, backdrop click, or Esc. */
export function askConfirm(message: string): Promise<boolean> {
  return new Promise((resolve) => {
    if (!listener) {
      // Host not mounted (tests / stray early call): fall back to the browser dialog,
      // which works outside the Tauri shell.
      resolve(window.confirm(message));
      return;
    }
    listener({ id: ++seq, message, resolve });
  });
}

export function ConfirmHost() {
  const [ask, setAsk] = useState<Ask | null>(null);

  useEffect(() => {
    listener = (a) =>
      setAsk((cur) => {
        cur?.resolve(false); // a newer ask supersedes an unanswered one
        return a;
      });
    return () => {
      listener = null;
    };
  }, []);

  useEffect(() => {
    if (!ask) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        ask.resolve(false);
        setAsk(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ask]);

  if (!ask) return null;
  const done = (ok: boolean) => {
    ask.resolve(ok);
    setAsk(null);
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center">
      <button aria-label="Cancel" onClick={() => done(false)} className="absolute inset-0 bg-black/50" />
      <div
        role="alertdialog"
        aria-modal="true"
        className="relative w-[440px] max-w-[calc(100vw-2rem)] rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] p-4 shadow-xl"
      >
        <p className="whitespace-pre-wrap text-sm text-[var(--text-primary)]">{ask.message}</p>
        <div className="mt-4 flex justify-end gap-2">
          <button className={btnCls} onClick={() => done(false)}>
            Cancel
          </button>
          <button className={btnCls} onClick={() => done(true)} autoFocus>
            OK
          </button>
        </div>
      </div>
    </div>
  );
}
