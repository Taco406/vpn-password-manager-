import { useEffect, useState } from "react";
import { Globe, Wifi, ShieldOff, Puzzle, X } from "lucide-react";
import {
  bridge,
  autofillStatus,
  autofillInstall,
  autofillUninstall,
  autofillPrepare,
  openFolder,
  netStatus,
  netSet,
  killswitchClear,
  vpnRealEnabled,
  vpnConnectMultihop,
  type NetStatusInfo,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { Toggle, inputCls, btnCls, errMsg } from "../components/kit";

export function Experimental() {
  return (
    <div className="mx-auto max-w-2xl px-8 py-8">
      <SectionTitle>Experimental</SectionTitle>

      <p className="mb-4 rounded-[10px] border border-[var(--warn)]/30 bg-[var(--warn)]/10 p-3 text-xs text-[var(--text-secondary)]">
        These are beta, Windows-first features that are still evolving — they may change, move, or
        break between releases. Try them out, but don't rely on them yet.
      </p>

      <NetGuard />
      <MultiHop />
      <BrowserAutofill />
    </div>
  );
}

function NetGuard() {
  const [status, setStatus] = useState<NetStatusInfo | null>(null);
  const [ssids, setSsids] = useState<string[]>([]);
  const [newSsid, setNewSsid] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    const [st, settings] = await Promise.all([netStatus(), bridge.settingsGet()]);
    setStatus(st);
    setSsids(settings.ssidAllowlist ?? []);
  };

  useEffect(() => {
    void refresh().catch(() => {});
  }, []);

  const persist = async (autoConnect: boolean, list: string[]) => {
    setBusy(true);
    setMsg("");
    try {
      await netSet(autoConnect, list);
      await refresh();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const auto = status?.autoConnect ?? false;

  const toggleAuto = () => void persist(!auto, ssids);

  const addSsid = (raw?: string) => {
    const v = (raw ?? newSsid).trim();
    setNewSsid("");
    if (!v || ssids.some((s) => s.toLowerCase() === v.toLowerCase())) return;
    const list = [...ssids, v];
    setSsids(list);
    void persist(auto, list);
  };

  const removeSsid = (s: string) => {
    const list = ssids.filter((x) => x !== s);
    setSsids(list);
    void persist(auto, list);
  };

  const clearKs = async () => {
    setBusy(true);
    setMsg("");
    try {
      await killswitchClear();
      setMsg("Kill-switch firewall rules cleared. If your connection was blocked, it's unblocked now.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const untrustedNow = !!status?.ssid && !status.trusted;

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Wifi size={15} /> Auto-connect &amp; kill switch
        </span>
        <Badge tone={auto ? "ok" : "accent"}>{auto ? "On · untrusted Wi-Fi" : "Off"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental (Windows-first) and only active in real-VPN (Linode) mode. When on, SENTINEL
        watches your Wi-Fi and automatically spins up the tunnel to your default region whenever
        you join a network that isn't on your trusted list — coffee shops, airports, hotels. It
        never auto-connects on a trusted network, and it waits a few minutes after you manually
        disconnect so it won't fight you.
      </p>

      <Toggle label="Auto-connect on untrusted Wi-Fi" checked={auto} onChange={toggleAuto} />

      {/* current network */}
      <div className="mt-3 flex items-center justify-between rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-sm">
        <span className="text-[var(--text-secondary)]">
          Current network:{" "}
          {status?.ssid ? (
            <span className="mono text-[var(--text-primary)]">{status.ssid}</span>
          ) : (
            <span className="text-[var(--text-muted)]">not on Wi-Fi</span>
          )}
        </span>
        {status?.ssid &&
          (status.trusted ? (
            <Badge tone="ok">Trusted</Badge>
          ) : (
            <Badge tone="accent">Untrusted</Badge>
          ))}
      </div>

      {/* trusted SSID editor */}
      <div className="mt-3">
        <div className="mb-1 text-xs text-[var(--text-muted)]">Trusted networks (no auto-connect)</div>
        {ssids.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-1.5">
            {ssids.map((s) => (
              <span
                key={s}
                className="inline-flex items-center gap-1 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2.5 py-1 text-xs"
              >
                <span className="mono">{s}</span>
                <button
                  onClick={() => removeSsid(s)}
                  disabled={busy}
                  aria-label={`Remove ${s}`}
                  className="text-[var(--text-muted)] hover:text-[var(--danger)] disabled:opacity-50"
                >
                  <X size={12} />
                </button>
              </span>
            ))}
          </div>
        )}
        <div className="flex items-center gap-2">
          <input
            value={newSsid}
            onChange={(e) => setNewSsid(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addSsid();
              }
            }}
            placeholder="Wi-Fi name (SSID)"
            className={`${inputCls} flex-1`}
          />
          <button onClick={() => addSsid()} disabled={busy || !newSsid.trim()} className={btnCls}>
            Add
          </button>
          {untrustedNow && (
            <button
              onClick={() => addSsid(status?.ssid ?? undefined)}
              disabled={busy}
              className={btnCls}
              title="Trust the network you're on right now"
            >
              Trust current
            </button>
          )}
        </div>
      </div>

      {/* kill-switch panic button */}
      <div className="mt-4 border-t border-[var(--border-subtle)] pt-4">
        <div className="mb-1 flex items-center gap-2 text-sm font-medium">
          <ShieldOff size={15} /> Kill switch
        </div>
        <p className="mb-2 text-xs text-[var(--text-secondary)]">
          When the kill switch is on (Security → &ldquo;Kill switch on by default&rdquo;), connecting
          adds Windows Firewall rules that block traffic outside the tunnel, so a dropped VPN can't
          leak. SENTINEL removes them on disconnect, on launch, and on exit. If you ever get stuck
          without internet, this button force-removes every rule right away.
        </p>
        <button onClick={clearKs} disabled={busy} className={btnCls}>
          {busy ? "Working…" : "Clear kill-switch rules"}
        </button>
      </div>

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
    </Card>
  );
}

function BrowserAutofill() {
  const [installed, setInstalled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [extPath, setExtPath] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void autofillStatus()
      .then((s) => setInstalled(s.installed))
      .catch(() => {});
  }, []);

  // Step 1: unpack the bundled extension to a stable folder + register the host, so the only
  // thing left for the user is the browser's one-time "Load unpacked".
  const getExtension = async () => {
    setBusy(true);
    setStatus("");
    try {
      const path = await autofillPrepare();
      setExtPath(path);
      if (!installed) await autofillInstall();
      const s = await autofillStatus();
      setInstalled(s.installed);
      setStatus("Ready — now load the folder in your browser (steps below).");
    } catch (e) {
      setStatus(`Couldn't prepare: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  const disable = async () => {
    setBusy(true);
    setStatus("");
    try {
      await autofillUninstall();
      const s = await autofillStatus();
      setInstalled(s.installed);
      setStatus("Disabled. Chrome and Edge will no longer talk to SENTINEL.");
    } catch (e) {
      setStatus(`Couldn't disable: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  const copyPath = async () => {
    try {
      await navigator.clipboard.writeText(extPath);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; the path is shown for manual copy */
    }
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Puzzle size={15} /> Browser autofill
        </span>
        <Badge tone={installed ? "ok" : "accent"}>{installed ? "On · Chrome + Edge" : "Off"}</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Experimental (Windows-first). Fill logins straight into Chrome and Edge. SENTINEL acts as
        the browser's native-messaging host itself — no extra program to install. A site only ever
        receives its own credentials, and nothing is available while the vault is locked.
      </p>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <button onClick={getExtension} disabled={busy} className={btnCls}>
          {busy ? "Working…" : installed ? "Re-copy extension files" : "Get the extension"}
        </button>
        {installed && (
          <button onClick={disable} disabled={busy} className={btnCls}>
            Disable
          </button>
        )}
        {status && <span className="text-xs text-[var(--text-muted)]">{status}</span>}
      </div>

      {extPath && (
        <div className="mb-3 rounded-[10px] border border-[var(--border-strong)] p-3">
          <div className="mb-2 text-xs text-[var(--text-secondary)]">
            Extension folder (you'll select this in your browser):
          </div>
          <div className="mb-2 flex items-center gap-2">
            <code className="mono flex-1 truncate rounded bg-[var(--bg-inset)] px-2 py-1 text-xs">
              {extPath}
            </code>
            <button onClick={copyPath} className="text-xs text-[var(--accent)] hover:underline">
              {copied ? "Copied" : "Copy path"}
            </button>
            <button
              onClick={() => void openFolder(extPath)}
              className="text-xs text-[var(--accent)] hover:underline"
            >
              Open folder
            </button>
          </div>
          <ol className="list-decimal space-y-1 pl-5 text-xs text-[var(--text-secondary)]">
            <li>
              Open <span className="mono">chrome://extensions</span> (or{" "}
              <span className="mono">edge://extensions</span>).
            </li>
            <li>
              Turn on <span className="mono">Developer mode</span> (top-right).
            </li>
            <li>
              Click <span className="mono">Load unpacked</span> and select the folder above.
            </li>
          </ol>
        </div>
      )}
    </Card>
  );
}

function MultiHop() {
  const [enabled, setEnabled] = useState(false);
  const [regions, setRegions] = useState<{ id: string; label: string }[]>([]);
  const [hops, setHops] = useState<string[]>(["", ""]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const on = await vpnRealEnabled();
        setEnabled(on);
        if (on) {
          const rs = await bridge.vpnRegions();
          const opts = rs.map((r) => ({ id: r.id, label: r.label ?? r.id }));
          setRegions(opts);
          if (opts.length >= 2) setHops([opts[0].id, opts[1].id]);
        }
      } catch {
        /* ignore */
      }
    })();
  }, []);

  if (!enabled) return null;

  const setHop = (i: number, v: string) => setHops((h) => h.map((x, j) => (j === i ? v : x)));
  const addHop = () => setHops((h) => (h.length < 3 ? [...h, regions[0]?.id ?? ""] : h));
  const removeHop = () => setHops((h) => (h.length > 2 ? h.slice(0, -1) : h));

  const connect = async () => {
    if (hops.some((h) => !h)) {
      setMsg("Pick a region for each hop.");
      return;
    }
    setBusy(true);
    setMsg("Building the chain… this provisions one node per hop and can take a minute.");
    try {
      await vpnConnectMultihop(hops);
      setMsg("Connected through the chain. Disconnect on the VPN screen destroys every hop.");
    } catch (e) {
      setMsg(`Couldn't connect: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Globe size={15} /> Multi-hop (bounce)
        </span>
        <Badge tone="warn">experimental</Badge>
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Route your traffic through 2–3 exit nodes in a row (entry → exit). More privacy, but{" "}
        <span className="font-medium">cost is N× a single node</span> and latency adds up. One local
        tunnel; the hops chain server-side. Windows-first and experimental — first real use is a test.
      </p>
      <div className="space-y-2">
        {hops.map((h, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="w-14 text-[var(--text-muted)]">
              {i === 0 ? "Entry" : i === hops.length - 1 ? "Exit" : `Hop ${i + 1}`}
            </span>
            <select
              value={h}
              onChange={(e) => setHop(i, e.target.value)}
              className="flex-1 rounded-[10px] border border-[var(--border-subtle)] bg-transparent px-2 py-1.5"
            >
              {regions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button onClick={connect} disabled={busy} className="rounded-[10px] bg-[var(--accent)] px-3 py-2 text-sm text-black disabled:opacity-50">
          {busy ? "Connecting…" : `Connect · ${hops.length} hops`}
        </button>
        {hops.length < 3 && (
          <button onClick={addHop} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
            + hop
          </button>
        )}
        {hops.length > 2 && (
          <button onClick={removeHop} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
            − hop
          </button>
        )}
        {msg && <span className="text-xs text-[var(--text-muted)]">{msg}</span>}
      </div>
    </Card>
  );
}
