// A tiny app-wide toast system. Screens call `toast()`/`toastError()` from anywhere (no context
// plumbing, matching the functional bridge style); one <Toaster/> mounted in App renders the stack.
// This replaces the ad-hoc per-screen `msg` strings that previously swallowed feedback.

import { useEffect, useState } from "react";
import { CheckCircle2, AlertTriangle, Info, X } from "lucide-react";
import { errMsg } from "./kit";

type ToastKind = "success" | "error" | "info";
interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

let listeners: ((t: ToastItem) => void)[] = [];
let seq = 0;

/** Show a transient toast. Safe to call from anywhere, including outside React. */
export function toast(message: string, kind: ToastKind = "info"): void {
  if (!message) return;
  const item = { id: ++seq, kind, message };
  listeners.forEach((l) => l(item));
}
export const toastSuccess = (message: string) => toast(message, "success");
/** Convenience for `catch` blocks: stringify any error and show it. */
export const toastError = (e: unknown) => toast(errMsg(e), "error");

const TONE: Record<ToastKind, { color: string; Icon: typeof Info }> = {
  success: { color: "var(--ok)", Icon: CheckCircle2 },
  error: { color: "var(--danger)", Icon: AlertTriangle },
  info: { color: "var(--accent)", Icon: Info },
};

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([]);

  useEffect(() => {
    const on = (t: ToastItem) => {
      setItems((prev) => [...prev, t]);
      window.setTimeout(() => setItems((prev) => prev.filter((x) => x.id !== t.id)), 4000);
    };
    listeners.push(on);
    return () => {
      listeners = listeners.filter((l) => l !== on);
    };
  }, []);

  const dismiss = (id: number) => setItems((prev) => prev.filter((x) => x.id !== id));

  if (items.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[320px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      {items.map((t) => {
        const { color, Icon } = TONE[t.kind];
        return (
          <div
            key={t.id}
            role="status"
            className="pointer-events-auto flex items-start gap-2 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-3 py-2.5 shadow-lg"
          >
            <Icon size={16} style={{ color }} className="mt-0.5 shrink-0" />
            <span className="min-w-0 flex-1 break-words text-xs text-[var(--text-primary)]">{t.message}</span>
            <button
              onClick={() => dismiss(t.id)}
              className="shrink-0 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              aria-label="Dismiss"
            >
              <X size={13} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
