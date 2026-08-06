// The embedded SSH root terminal (v0.1.64). Lives in the server side-panel's
// Access tab. A real interactive PTY via xterm.js: keystrokes go to the backend
// russh session, output streams back over Tauri events. Everything security-
// relevant (host-key pinning, the biometric gate, kill-on-lock) is enforced in
// the Rust backend; this component is the surface.

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { TerminalSquare, ShieldCheck, KeyRound, ChevronDown, ChevronRight } from "lucide-react";
import {
  sshPubkey,
  sshOpen,
  sshWrite,
  sshResize,
  sshClose,
  onSshData,
  onSshClosed,
  serversSshStatus,
  serversSshMarkInstalled,
  serversSshHostkeyReset,
  sshAuditRead,
  sshAuditClear,
  type ManagedServer,
} from "../bridge";
import { btnCls, errMsg } from "./kit";
import { toastError } from "./Toast";

// base64 <-> bytes. Keystrokes are tiny; output chunks are modest, so the simple
// char-by-char form is fine (and avoids apply()-on-huge-array stack limits).
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function CopyBtn({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className={btnCls}
      onClick={async () => {
        await navigator.clipboard?.writeText(text);
        setDone(true);
        window.setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

export function SshTerminal({ s }: { s: ManagedServer }) {
  const host = s.ipv4 ?? "";
  const mountRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const sessionRef = useRef<string | null>(null);
  const unsubRef = useRef<Array<() => void>>([]);

  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [fingerprint, setFingerprint] = useState("");
  const [justPinned, setJustPinned] = useState(false);
  const [err, setErr] = useState("");

  const [pubkey, setPubkey] = useState("");
  const [installed, setInstalled] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [audit, setAudit] = useState("");

  // Pull saved status (pinned fingerprint + install flag) on mount.
  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const st = await serversSshStatus(s.provider, s.id);
        if (!alive) return;
        setFingerprint(st.fingerprint);
        setInstalled(st.installed);
      } catch {
        /* status is best-effort */
      }
    })();
    return () => {
      alive = false;
    };
  }, [s.provider, s.id]);

  const teardown = useCallback(() => {
    unsubRef.current.forEach((u) => u());
    unsubRef.current = [];
    termRef.current?.dispose();
    termRef.current = null;
    fitRef.current = null;
    sessionRef.current = null;
    setConnected(false);
  }, []);

  // Dispose on unmount (drawer close / navigation). The backend also kills the
  // session on vault lock, independently of this.
  useEffect(() => {
    return () => {
      const sid = sessionRef.current;
      if (sid) void sshClose(sid);
      teardown();
    };
  }, [teardown]);

  const loadPubkey = useCallback(async () => {
    try {
      setPubkey(await sshPubkey());
    } catch (e) {
      toastError(errMsg(e));
    }
  }, []);

  const connect = useCallback(async () => {
    if (!host) {
      setErr("This server has no public IP address.");
      return;
    }
    setErr("");
    setConnecting(true);
    try {
      // Connect + authenticate + open the PTY first. This also runs the biometric
      // gate, so it can take a moment — during which the (empty) terminal box is
      // already visible, so xterm can size itself correctly against a laid-out
      // element (fit() on a display:none container yields a 0×0 viewport).
      const out = await sshOpen(s.provider, s.id, host);
      sessionRef.current = out.sessionId;
      setFingerprint(out.fingerprint);
      setJustPinned(out.firstConnect);

      const term = new Terminal({
        fontSize: 13,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        cursorBlink: true,
        theme: { background: "#0b0f17" },
        scrollback: 5000,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      if (mountRef.current) {
        term.open(mountRef.current);
        fit.fit();
      }
      termRef.current = term;
      fitRef.current = fit;

      const unData = await onSshData(out.sessionId, (b64) => {
        term.write(b64ToBytes(b64));
      });
      const unClosed = await onSshClosed(out.sessionId, () => {
        term.write("\r\n\x1b[38;5;244m[session closed]\x1b[0m\r\n");
        teardown();
      });
      unsubRef.current = [unData, unClosed];

      // Wire input + resize now that we have a session id.
      term.onData((data) => {
        const sid = sessionRef.current;
        if (sid) void sshWrite(sid, bytesToB64(new TextEncoder().encode(data)));
      });
      term.onResize(({ cols, rows }) => {
        const sid = sessionRef.current;
        if (sid) void sshResize(sid, cols, rows);
      });
      // Push the true size to the remote PTY (opened at a default 80x24), then a
      // newline so a fresh prompt appears — the shell's initial prompt may have
      // been emitted before our listener above was registered.
      fit.fit();
      void sshResize(out.sessionId, term.cols, term.rows);
      void sshWrite(out.sessionId, bytesToB64(new TextEncoder().encode("\n")));
      term.focus();
      setConnected(true);
    } catch (e) {
      setErr(errMsg(e));
      teardown();
    } finally {
      setConnecting(false);
    }
  }, [host, s.provider, s.id, teardown]);

  const disconnect = useCallback(() => {
    const sid = sessionRef.current;
    if (sid) void sshClose(sid);
    teardown();
  }, [teardown]);

  // Keep the terminal fitted to its container.
  useEffect(() => {
    if (!connected) return;
    const onResize = () => fitRef.current?.fit();
    window.addEventListener("resize", onResize);
    const ro = new ResizeObserver(() => fitRef.current?.fit());
    if (mountRef.current) ro.observe(mountRef.current);
    return () => {
      window.removeEventListener("resize", onResize);
      ro.disconnect();
    };
  }, [connected]);

  const installCmd = pubkey
    ? `mkdir -p ~/.ssh && echo '${pubkey}' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`
    : "";

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <TerminalSquare size={14} /> Terminal
      </div>
      <p className="text-xs text-[var(--text-secondary)]">
        A live root shell on {host || "this server"}, inside NorthKey. The connection is verified
        against a key fingerprint pinned on first connect, and closes automatically when you lock
        your vault.
      </p>

      {/* First-time setup: install NorthKey's public key. */}
      <div className="rounded-[10px] border border-[var(--border)]">
        <button
          className="flex w-full items-center gap-2 px-3 py-2 text-xs font-medium"
          onClick={() => {
            setShowSetup((v) => !v);
            if (!pubkey) void loadPubkey();
          }}
        >
          {showSetup ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <KeyRound size={13} /> Set up access {installed && <span className="text-[var(--ok)]">· done</span>}
        </button>
        {showSetup && (
          <div className="space-y-2 border-t border-[var(--border)] p-3 text-xs">
            <p className="text-[var(--text-secondary)]">
              Run this once on the server (it adds NorthKey's key so it can sign in without a
              password). You can paste it into the pop-out terminal above.
            </p>
            <pre className="mono max-h-24 overflow-auto rounded bg-[var(--bg-tertiary)] p-2 text-[11px]">
              {installCmd || "…"}
            </pre>
            <div className="flex items-center gap-2">
              <CopyBtn text={installCmd} label="Copy command" />
              <CopyBtn text={pubkey} label="Copy key only" />
              <label className="ml-auto inline-flex items-center gap-1 text-[var(--text-secondary)]">
                <input
                  type="checkbox"
                  checked={installed}
                  onChange={async (e) => {
                    setInstalled(e.target.checked);
                    await serversSshMarkInstalled(s.provider, s.id, e.target.checked);
                  }}
                />
                I&apos;ve installed it
              </label>
            </div>
          </div>
        )}
      </div>

      {/* Host-key fingerprint. */}
      {fingerprint && (
        <div
          className={`rounded-[10px] border p-2 text-[11px] ${
            justPinned
              ? "border-[var(--accent)]/40 bg-[var(--accent)]/10"
              : "border-[var(--border)] text-[var(--text-muted)]"
          }`}
        >
          <div className="flex items-center gap-1">
            <ShieldCheck size={12} />
            <span className="mono">{fingerprint}</span>
          </div>
          {justPinned && (
            <p className="mt-1 text-[var(--text-secondary)]">
              First connection — NorthKey pinned this server&apos;s key. If you have another way to
              check it, verify it now. Future connections refuse if it changes.
            </p>
          )}
        </div>
      )}

      {err && (
        <div className="whitespace-pre-wrap rounded-[10px] border border-[var(--danger)]/40 bg-[var(--danger)]/10 p-2 text-[11px] text-[var(--danger)]">
          {err}
        </div>
      )}

      <div className="flex items-center gap-2">
        {connected ? (
          <button className={btnCls} onClick={disconnect}>
            Disconnect
          </button>
        ) : (
          <button className={btnCls} disabled={connecting || !host} onClick={() => void connect()}>
            {connecting ? "Connecting…" : "Connect"}
          </button>
        )}
        {connecting && (
          <span className="text-[11px] text-[var(--text-muted)]">
            connecting… (on Windows, confirm the Hello prompt)
          </span>
        )}
      </div>

      {/* xterm mount — shown from the moment we start connecting so xterm sizes
          against a laid-out element, hidden only when fully disconnected. */}
      <div
        ref={mountRef}
        className={`overflow-hidden rounded-[10px] border border-[var(--border)] bg-[#0b0f17] ${
          connecting || connected ? "h-80 p-1" : "hidden"
        }`}
      />

      {/* Advanced: reset pinned key + audit log. */}
      <div className="rounded-[10px] border border-[var(--border)]">
        <button
          className="flex w-full items-center gap-2 px-3 py-2 text-xs font-medium"
          onClick={() => {
            setShowAdvanced((v) => !v);
            if (!audit) void sshAuditRead().then(setAudit);
          }}
        >
          {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />} Advanced
        </button>
        {showAdvanced && (
          <div className="space-y-3 border-t border-[var(--border)] p-3 text-xs">
            <div>
              <p className="mb-1 text-[var(--text-secondary)]">
                Rebuilt this server? Reset its pinned key so the next connection trusts the new one.
              </p>
              <button
                className={btnCls}
                onClick={async () => {
                  try {
                    await serversSshHostkeyReset(s.provider, s.id);
                    setFingerprint("");
                    setJustPinned(false);
                  } catch (e) {
                    toastError(errMsg(e));
                  }
                }}
              >
                Reset pinned key
              </button>
            </div>
            <div>
              <div className="mb-1 flex items-center gap-2">
                <span className="text-[var(--text-secondary)]">
                  Terminal history (stays on this computer)
                </span>
                <button
                  className="ml-auto text-[var(--accent)] hover:underline"
                  onClick={async () => {
                    await sshAuditClear();
                    setAudit("");
                  }}
                >
                  Clear
                </button>
              </div>
              <pre className="max-h-40 overflow-auto rounded bg-[var(--bg-tertiary)] p-2 text-[10px] text-[var(--text-muted)]">
                {audit.trim() || "No sessions recorded yet."}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
