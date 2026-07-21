// The Servers screen: every server the user owns — all Linode instances (including
// NorthKey's own VPN/sync nodes, labeled by role) and all Hetzner Cloud servers — with
// power actions and real utilization graphs from the provider metrics APIs.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Server,
  RefreshCw,
  Copy as CopyIcon,
  ChevronDown,
  ChevronRight,
  Activity,
  BellRing,
  Copy,
} from "lucide-react";
import {
  serversConfig,
  serversList,
  serversMetrics,
  serversPower,
  serversWatchdogGet,
  serversWatchdogSet,
  netdataGet,
  netdataSet,
  netdataProbe,
  netdataMetric,
  netdataAlarms,
  onServersAlert,
  netMyIp,
  type ManagedServer,
  type ServerMetricsOut,
  type NetdataCfg,
  type NetdataProbe,
  type WatchdogCfg,
  type ServerAlert,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { errMsg, inputCls, btnCls, Toggle } from "../components/kit";
import { TimeSeriesChart } from "../components/charts/TimeSeriesChart";
import { ThroughputChart } from "../components/charts/ThroughputChart";

const LIST_REFRESH_MS = 60_000;
const METRICS_REFRESH_MS = 60_000;

const WINDOWS: { label: string; secs: number }[] = [
  { label: "1h", secs: 3600 },
  { label: "6h", secs: 6 * 3600 },
  { label: "24h", secs: 24 * 3600 },
];

export function Servers() {
  const [cfg, setCfg] = useState<{ linodeEnabled: boolean; hetznerEnabled: boolean } | null>(null);
  const [servers, setServers] = useState<ManagedServer[]>([]);
  const [provErrors, setProvErrors] = useState<{ provider: string; message: string }[]>([]);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const c = await serversConfig();
      setCfg(c);
      if (!c.linodeEnabled && !c.hetznerEnabled) {
        setLoaded(true);
        return;
      }
      const r = await serversList();
      setServers(r.servers);
      setProvErrors(r.errors);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setLoaded(true);
  }, []);

  useEffect(() => {
    void refresh();
    const t = window.setInterval(() => void refresh(), LIST_REFRESH_MS);
    return () => window.clearInterval(t);
  }, [refresh]);

  const act = async (s: ManagedServer, action: "start" | "stop" | "reboot") => {
    const warn =
      action === "stop"
        ? `Stop "${s.label}"? A stopped server usually still bills until destroyed.`
        : `${action === "start" ? "Start" : "Reboot"} "${s.label}"?`;
    if (!window.confirm(warn)) return;
    setBusy(true);
    setMsg("");
    try {
      await serversPower(s.provider, s.id, action);
      setMsg(`${action} requested for ${s.label}. State updates in a few seconds.`);
      window.setTimeout(() => void refresh(), 4000);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  // Per-currency cost strip (never sum USD + EUR together).
  const byCurrency = new Map<string, { monthly: number; count: number }>();
  for (const s of servers) {
    const e = byCurrency.get(s.currency) ?? { monthly: 0, count: 0 };
    e.monthly += s.monthly;
    e.count += 1;
    byCurrency.set(s.currency, e);
  }
  const running = servers.filter((s) => s.state === "running").length;
  const sym = (c: string) => (c === "EUR" ? "€" : "$");

  const noTokens = cfg && !cfg.linodeEnabled && !cfg.hetznerEnabled;

  return (
    <div className="mx-auto max-w-4xl px-8 py-8">
      <SectionTitle hint="Linode · Hetzner Cloud">Servers</SectionTitle>

      {noTokens && (
        <Card>
          <div className="mb-2 flex items-center gap-2 text-sm font-medium">
            <Server size={15} /> Manage every server you own, in one place
          </div>
          <p className="text-xs text-[var(--text-secondary)]">
            Add your <span className="font-medium">Linode</span> API token (Settings → VPN → Real VPN)
            and/or your <span className="font-medium">Hetzner Cloud</span> API token (Settings → VPN →
            Hetzner Cloud) and this screen lists all your servers with live state, real CPU/network
            graphs, and start/stop/reboot controls.
          </p>
        </Card>
      )}

      {!noTokens && loaded && (
        <>
          <Card className="mb-4 !p-4">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-xs text-[var(--text-secondary)]">
              <span>
                <span className="mono text-[var(--text-primary)]">{servers.length}</span> server
                {servers.length === 1 ? "" : "s"} ·{" "}
                <span className="mono text-[var(--text-primary)]">{running}</span> running
              </span>
              {[...byCurrency.entries()].map(([cur, v]) => (
                <span key={cur}>
                  {sym(cur)}
                  <span className="mono text-[var(--text-primary)]">{v.monthly.toFixed(2)}</span>/mo ({v.count}× {cur})
                </span>
              ))}
              <button
                onClick={() => void refresh()}
                className="ml-auto inline-flex items-center gap-1 text-[var(--accent)] hover:underline"
              >
                <RefreshCw size={12} /> Refresh
              </button>
            </div>
          </Card>

          {provErrors.map((e) => (
            <Card key={e.provider} className="mb-4 border border-[var(--warn)]/40">
              <p className="text-xs text-[var(--warn)]">
                {e.provider}: {e.message}
              </p>
            </Card>
          ))}

          {servers.map((s) => (
            <ServerRow key={`${s.provider}:${s.id}`} s={s} busy={busy} onAct={act} />
          ))}

          {servers.length === 0 && provErrors.length === 0 && (
            <Card>
              <p className="text-xs text-[var(--text-muted)]">No servers found on your accounts.</p>
            </Card>
          )}

          <WatchdogCard />
          <AlertFeed />
        </>
      )}

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
    </div>
  );
}

function roleTone(role: string): "accent" | "ok" | "neutral" {
  if (role === "external") return "neutral";
  return role === "sync" ? "ok" : "accent";
}

function stateTone(state: string): "ok" | "neutral" | "accent" | "danger" {
  if (state === "running") return "ok";
  if (state === "stopped") return "neutral";
  if (state === "gone" || state === "deleting") return "danger";
  return "accent";
}

function ServerRow({
  s,
  busy,
  onAct,
}: {
  s: ManagedServer;
  busy: boolean;
  onAct: (s: ManagedServer, action: "start" | "stop" | "reboot") => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyIp = async () => {
    if (!s.ipv4) return;
    await navigator.clipboard?.writeText(s.ipv4);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <Card className="mb-3 !p-4">
      <div className="flex items-center gap-3">
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-[var(--text-muted)] hover:text-[var(--accent)]"
          aria-label={open ? "Collapse" : "Expand"}
        >
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium">{s.label}</span>
            <Badge tone={s.provider === "hetzner" ? "danger" : "accent"}>
              {s.provider === "hetzner" ? "Hetzner" : "Linode"}
            </Badge>
            {s.roles
              .filter((r) => r !== "external")
              .map((r) => (
                <Badge key={r} tone={roleTone(r)}>
                  {r}
                </Badge>
              ))}
            <Badge tone={stateTone(s.state)}>{s.state}</Badge>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-[var(--text-muted)]">
            <span className="mono">{s.region}</span>
            <span className="mono">{s.instanceType}</span>
            {s.vcpus > 0 && (
              <span>
                {s.vcpus} vCPU · {(s.memoryMb / 1024).toFixed(0)} GB · {s.diskGb} GB disk
              </span>
            )}
            {s.ipv4 && (
              <button onClick={() => void copyIp()} className="mono inline-flex items-center gap-1 hover:text-[var(--accent)]">
                {s.ipv4} <CopyIcon size={11} /> {copied && <span className="text-[var(--ok)]">copied</span>}
              </button>
            )}
            <span>
              {s.currency === "EUR" ? "€" : "$"}
              {s.monthly.toFixed(2)}/mo
            </span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-3 text-xs">
          {s.state === "stopped" ? (
            <button disabled={busy} onClick={() => void onAct(s, "start")} className="text-[var(--ok)] hover:underline disabled:opacity-50">
              Start
            </button>
          ) : (
            <button disabled={busy} onClick={() => void onAct(s, "stop")} className="text-[var(--text-secondary)] hover:underline disabled:opacity-50">
              Stop
            </button>
          )}
          <button disabled={busy || s.state === "stopped"} onClick={() => void onAct(s, "reboot")} className="text-[var(--accent)] hover:underline disabled:opacity-50">
            Reboot
          </button>
        </div>
      </div>

      {open && <ServerCharts s={s} />}
    </Card>
  );
}

function ServerCharts({ s }: { s: ManagedServer }) {
  const [metrics, setMetrics] = useState<ServerMetricsOut | null>(null);
  const [windowSecs, setWindowSecs] = useState(3600);
  const [err, setErr] = useState("");
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    const load = async () => {
      try {
        const m = await serversMetrics(s.provider, s.id, windowSecs);
        if (alive.current) {
          setMetrics(m);
          setErr("");
        }
      } catch (e) {
        if (alive.current) setErr(errMsg(e));
      }
    };
    void load();
    const t = window.setInterval(() => void load(), METRICS_REFRESH_MS);
    return () => {
      alive.current = false;
      window.clearInterval(t);
    };
  }, [s.provider, s.id, windowSecs]);

  return (
    <div className="mt-3 border-t border-[var(--border-subtle)] pt-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-medium text-[var(--text-secondary)]">Utilization</span>
        <div className="flex gap-1 rounded-[8px] bg-[var(--bg-inset)] p-0.5 text-[11px]">
          {WINDOWS.map((w) => (
            <button
              key={w.secs}
              onClick={() => setWindowSecs(w.secs)}
              className={`rounded-[6px] px-2 py-0.5 ${windowSecs === w.secs ? "bg-[var(--accent)]/15 text-[var(--accent)]" : "text-[var(--text-muted)]"}`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>
      {err && <p className="text-xs text-[var(--warn)]">{err}</p>}
      {!err && !metrics && <p className="text-xs text-[var(--text-muted)]">Loading metrics…</p>}
      {metrics && (
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <div className="mb-1 text-[11px] text-[var(--text-muted)]">CPU</div>
            <TimeSeriesChart
              unit="pct"
              height={140}
              series={[{ points: metrics.cpuPct, color: "#22d3ee", label: "cpu %" }]}
            />
          </div>
          <div>
            <div className="mb-1 text-[11px] text-[var(--text-muted)]">Network</div>
            <TimeSeriesChart
              unit="bps"
              height={140}
              series={[
                { points: metrics.netInBps, color: "#22d3ee", label: "in" },
                { points: metrics.netOutBps, color: "#a78bfa", label: "out" },
              ]}
            />
          </div>
        </div>
      )}
      {metrics && metrics.cpuPct.length === 0 && (
        <p className="mt-2 text-[11px] text-[var(--text-muted)]">
          No samples yet — providers only report metrics for running servers, and fresh servers can
          take a few minutes to produce data.
        </p>
      )}

      {s.ipv4 && <NetdataPanel s={s} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Netdata: live per-second monitoring for servers running the (free) Netdata agent.
// ---------------------------------------------------------------------------

function NetdataPanel({ s }: { s: ManagedServer }) {
  const [cfg, setCfg] = useState<NetdataCfg | null>(null);

  useEffect(() => {
    void netdataGet(s.provider, s.id).then(setCfg).catch(() => {});
  }, [s.provider, s.id]);

  if (!cfg) return null;
  return (
    <div className="mt-4 border-t border-[var(--border-subtle)] pt-3">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-[var(--text-secondary)]">
        <Activity size={13} /> Live monitoring (Netdata)
      </div>
      {cfg.enabled ? (
        <NetdataLive s={s} onDisable={() => setCfg({ ...cfg, enabled: false })} />
      ) : (
        <NetdataSetup s={s} cfg={cfg} onEnabled={(c) => setCfg(c)} />
      )}
    </div>
  );
}

function NetdataLive({ s, onDisable }: { s: ManagedServer; onDisable: () => void }) {
  const [cpu, setCpu] = useState<number[]>([]);
  const [pills, setPills] = useState<{ ram?: number; load?: number; disk?: number }>({});
  const [alarms, setAlarms] = useState<{ name: string; status: string; value: string }[]>([]);
  const [err, setErr] = useState("");
  const host = s.ipv4!;

  useEffect(() => {
    let alive = true;
    const cpuTick = async () => {
      try {
        const pts = await netdataMetric(s.provider, s.id, host, "cpu", 120, 60);
        if (alive) {
          setCpu(pts.map(([, v]) => v));
          setErr("");
        }
      } catch (e) {
        if (alive) setErr(errMsg(e));
      }
    };
    const pillsTick = async () => {
      try {
        const last = async (kind: string) =>
          (await netdataMetric(s.provider, s.id, host, kind, 15, 3)).at(-1)?.[1];
        const [ram, load, disk] = await Promise.all([last("ram"), last("load"), last("disk")]);
        if (alive) setPills({ ram, load, disk });
      } catch {
        /* pills are best-effort */
      }
    };
    const alarmsTick = async () => {
      try {
        const a = await netdataAlarms(s.provider, s.id, host);
        if (alive) setAlarms(a);
      } catch {
        /* best-effort */
      }
    };
    void cpuTick();
    void pillsTick();
    void alarmsTick();
    const t1 = window.setInterval(() => void cpuTick(), 2000);
    const t2 = window.setInterval(() => void pillsTick(), 10000);
    const t3 = window.setInterval(() => void alarmsTick(), 30000);
    return () => {
      alive = false;
      window.clearInterval(t1);
      window.clearInterval(t2);
      window.clearInterval(t3);
    };
  }, [s.provider, s.id, host]);

  const pill = (label: string, v: number | undefined, unit: string) => (
    <div className="rounded-[8px] bg-[var(--bg-inset)] px-2.5 py-1.5 text-[11px]">
      <span className="text-[var(--text-muted)]">{label} </span>
      <span className="mono">{v === undefined ? "—" : `${v.toFixed(unit === "" ? 2 : 0)}${unit}`}</span>
    </div>
  );

  return (
    <div>
      {err && (
        <p className="mb-2 text-[11px] text-[var(--warn)]">
          Netdata unreachable right now: {err}{" "}
          <button
            onClick={() => {
              void netdataSet(s.provider, s.id, { enabled: false, port: 19999, https: false, hasAuth: false });
              onDisable();
            }}
            className="text-[var(--accent)] hover:underline"
          >
            Reconfigure
          </button>
        </p>
      )}
      <div className="grid gap-4 md:grid-cols-[1fr_auto]">
        <div>
          <div className="mb-1 flex items-baseline justify-between text-[11px] text-[var(--text-muted)]">
            <span>CPU (per-second, live)</span>
            <span className="mono text-[var(--accent)]">{cpu.at(-1)?.toFixed(0) ?? "—"}%</span>
          </div>
          <ThroughputChart data={cpu.length ? cpu : [0, 0]} width={420} height={110} />
        </div>
        <div className="flex flex-row flex-wrap content-start gap-2 md:flex-col">
          {pill("RAM", pills.ram, "%")}
          {pill("Load", pills.load, "")}
          {pill("Disk /", pills.disk, "%")}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {alarms.length === 0 ? (
          <Badge tone="ok">no active alarms</Badge>
        ) : (
          alarms.map((a) => (
            <Badge key={a.name} tone={a.status === "CRITICAL" ? "danger" : "warn"}>
              {a.name}
              {a.value ? ` · ${a.value}` : ""}
            </Badge>
          ))
        )}
      </div>
    </div>
  );
}

function CopyLine({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-[8px] bg-[var(--bg-inset)] px-2 py-1.5">
      <code className="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap text-[11px] text-[var(--text-secondary)]">
        {text}
      </code>
      <button
        onClick={() => {
          void navigator.clipboard?.writeText(text);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        }}
        className="shrink-0 text-[var(--text-muted)] hover:text-[var(--accent)]"
        aria-label="Copy"
      >
        {copied ? <span className="text-[11px] text-[var(--ok)]">✓</span> : <Copy size={12} />}
      </button>
    </div>
  );
}

function NetdataSetup({
  s,
  cfg,
  onEnabled,
}: {
  s: ManagedServer;
  cfg: NetdataCfg;
  onEnabled: (c: NetdataCfg) => void;
}) {
  const [probing, setProbing] = useState(false);
  const [probe, setProbe] = useState<NetdataProbe | null>(null);
  const [myIp, setMyIp] = useState("<your-ip>");
  const [port, setPort] = useState(cfg.port);
  const [auth, setAuth] = useState("");
  const host = s.ipv4!;

  useEffect(() => {
    void netMyIp()
      .then((m) => setMyIp(m.ip))
      .catch(() => {});
  }, []);

  const runProbe = async () => {
    setProbing(true);
    try {
      // Persist any override the user typed before probing.
      if (port !== cfg.port || auth.trim()) {
        await netdataSet(s.provider, s.id, { ...cfg, port }, auth.trim() ? `Basic ${btoa(auth.trim())}` : undefined);
      }
      const p = await netdataProbe(s.provider, s.id, host);
      setProbe(p);
      if (p.reachable) {
        const enabled: NetdataCfg = { ...cfg, enabled: true, port, https: p.https };
        await netdataSet(s.provider, s.id, enabled);
        onEnabled(enabled);
      }
    } catch (e) {
      setProbe({ reachable: false, version: "", hostname: "", url: "", https: false, error: errMsg(e) });
    }
    setProbing(false);
  };

  return (
    <div className="space-y-2 text-[11px] text-[var(--text-secondary)]">
      <p>
        If this server runs the free <span className="font-medium">Netdata</span> agent, NorthKey can
        show per-second live CPU/RAM/disk/network and Netdata's own alarms. Nothing is installed from
        here — the app only reads Netdata's local API.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => void runProbe()} disabled={probing} className={btnCls}>
          {probing ? "Checking…" : `Check ${host}:${port}`}
        </button>
        <label className="flex items-center gap-1">
          port
          <input
            value={port}
            onChange={(e) => setPort(Number(e.target.value.replace(/\D/g, "")) || 19999)}
            className={`${inputCls} w-20 !py-1`}
          />
        </label>
        <input
          value={auth}
          onChange={(e) => setAuth(e.target.value)}
          placeholder="user:password (only if proxied behind auth)"
          className={`${inputCls} w-64 !py-1`}
        />
      </div>
      {probe && !probe.reachable && (
        <div className="space-y-2 rounded-[10px] border border-[var(--warn)]/40 bg-[var(--warn)]/10 p-2.5">
          <p className="text-[var(--warn)]">
            Couldn't reach Netdata at {probe.url} ({probe.error ?? "no response"}). Usually that means
            it isn't installed, or the port is firewalled. On the server (SSH in and paste):
          </p>
          <div className="space-y-1.5">
            <div>
              <span className="text-[var(--text-muted)]">Install Netdata (one line):</span>
              <CopyLine text="wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/netdata-kickstart.sh --non-interactive" />
            </div>
            <div>
              <span className="text-[var(--text-muted)]">
                Open port 19999 to YOUR IP only (ufw; safer than opening it to the world):
              </span>
              <CopyLine text={`ufw allow from ${myIp} to any port ${port} proto tcp`} />
            </div>
            <div>
              <span className="text-[var(--text-muted)]">
                Also allow the address Netdata binds (then re-check here):
              </span>
              <CopyLine text={`ssh root@${host}`} />
            </div>
          </div>
          <p className="text-[var(--text-muted)]">
            Alternative without opening any port: an SSH tunnel —{" "}
            <span className="mono">ssh -L 19999:localhost:19999 root@{host}</span> — but the app can
            only read it while the tunnel runs.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Watchdog config + session alert feed
// ---------------------------------------------------------------------------

function WatchdogCard() {
  const [cfg, setCfg] = useState<WatchdogCfg | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    void serversWatchdogGet().then(setCfg).catch(() => {});
  }, []);

  const patch = (p: Partial<WatchdogCfg>) => {
    if (!cfg) return;
    const next = { ...cfg, ...p };
    setCfg(next);
    void serversWatchdogSet(next).then(() => {
      setSaved(true);
      window.setTimeout(() => setSaved(false), 1200);
    });
  };

  if (!cfg) return null;
  const num = (v: string, fallback: number) => {
    const n = Number(v.replace(/\D/g, ""));
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };

  return (
    <Card className="mb-3 mt-6 !p-4">
      <div className="mb-1 flex items-center justify-between">
        <span className="flex items-center gap-2 text-sm font-medium">
          <BellRing size={15} /> Watchdog &amp; alerts
        </span>
        <Badge tone={cfg.enabled ? "ok" : "neutral"}>{cfg.enabled ? "On" : "Off"}</Badge>
      </div>
      <p className="mb-2 text-xs text-[var(--text-secondary)]">
        Checks all your servers in the background and fires a Windows notification when one goes
        down (and when it recovers), when CPU stays pegged, when a disk runs full, or when Netdata
        raises an alarm. Alerts fire only while NorthKey is running.
      </p>
      <Toggle label="Watch my servers in the background" checked={cfg.enabled} onChange={(v) => patch({ enabled: v })} />
      {cfg.enabled && (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-[var(--text-muted)]">
          <label className="flex items-center gap-1.5">
            check every
            <input
              value={cfg.intervalSecs}
              onChange={(e) => patch({ intervalSecs: Math.max(60, num(e.target.value, 120)) })}
              className={`${inputCls} w-16 !py-1`}
            />
            s
          </label>
          <label className="flex items-center gap-1.5">
            CPU &gt;
            <input
              value={cfg.cpuPct}
              onChange={(e) => patch({ cpuPct: Math.min(100, num(e.target.value, 90)) })}
              className={`${inputCls} w-14 !py-1`}
            />
            %
          </label>
          <label className="flex items-center gap-1.5">
            disk &gt;
            <input
              value={cfg.diskPct}
              onChange={(e) => patch({ diskPct: Math.min(100, num(e.target.value, 90)) })}
              className={`${inputCls} w-14 !py-1`}
            />
            %
          </label>
          {saved && <span className="text-[var(--ok)]">saved</span>}
        </div>
      )}
      <p className="mt-2 text-[11px] text-[var(--text-muted)]">
        CPU and disk alerts need Netdata enabled on the server (expand a server row → Live
        monitoring). Down/recovered alerts work for every server, no Netdata needed.
      </p>
    </Card>
  );
}

function AlertFeed() {
  const [alerts, setAlerts] = useState<ServerAlert[]>([]);

  useEffect(() => {
    let un: (() => void) | undefined;
    void onServersAlert((a) => setAlerts((prev) => [a, ...prev].slice(0, 20))).then((f) => (un = f));
    return () => un?.();
  }, []);

  if (alerts.length === 0) return null;
  const tone = (kind: string) =>
    kind === "recovered" ? "ok" : kind === "down" ? "danger" : "warn";
  return (
    <Card className="mb-3 !p-4">
      <div className="mb-2 text-sm font-medium">Recent alerts</div>
      <div className="space-y-1.5">
        {alerts.map((a, i) => (
          <div key={`${a.ts}-${i}`} className="flex items-center gap-2 text-xs">
            <Badge tone={tone(a.kind) as "ok" | "danger" | "warn"}>{a.kind}</Badge>
            <span className="text-[var(--text-secondary)]">{a.message}</span>
            <span className="ml-auto mono text-[10px] text-[var(--text-muted)]">
              {new Date(a.ts * 1000).toLocaleTimeString()}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}
