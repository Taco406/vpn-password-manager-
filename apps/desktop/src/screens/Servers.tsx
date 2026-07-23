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
  Camera,
  ShieldCheck,
  Globe,
  History,
  TerminalSquare,
} from "lucide-react";
import {
  serversConfig,
  serversList,
  serversMetrics,
  serversPower,
  serversSnapshot,
  serversListSnapshots,
  serversEvents,
  serversSetRdns,
  serversSetProtection,
  serversOpenTerminal,
  serversWatchdogGet,
  serversWatchdogSet,
  netdataGet,
  netdataSet,
  netdataProbe,
  netdataMetric,
  netdataSeries,
  netdataAlarms,
  serversFirewallGet,
  serversFirewallAllowPort,
  onServersAlert,
  onSyncApplied,
  netMyIp,
  type ManagedServer,
  type ServerMetricsOut,
  type Snapshot,
  type ServerEventItem,
  type NetdataCfg,
  type NetdataProbe,
  type NetdataSeriesLine,
  type FirewallStatus,
  type WatchdogCfg,
  type ServerAlert,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { errMsg, inputCls, btnCls, Toggle } from "../components/kit";
import { TimeSeriesChart, type TimeSeries } from "../components/charts/TimeSeriesChart";
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
    // The auto-sync poller applies synced provider tokens (Linode/Hetzner) in the background;
    // refresh the moment it does so this screen populates itself right after sign-in — no manual sync.
    let unsub: (() => void) | undefined;
    void onSyncApplied(() => void refresh()).then((u) => (unsub = u));
    return () => {
      window.clearInterval(t);
      unsub?.();
    };
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

      <ServerLifecycle s={s} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stage 3: per-server lifecycle — snapshots, protection, reverse DNS, activity,
// and SSH access. Collapsed by default so it only hits the provider APIs on demand.
// ---------------------------------------------------------------------------

function fmtWhen(unix: number | null): string {
  if (!unix) return "";
  const secs = Math.floor(Date.now() / 1000) - unix;
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function ServerLifecycle({ s }: { s: ManagedServer }) {
  const [open, setOpen] = useState(false);
  const [snaps, setSnaps] = useState<Snapshot[] | null>(null);
  const [events, setEvents] = useState<ServerEventItem[] | null>(null);
  const [label, setLabel] = useState("");
  const [ptr, setPtr] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const isHetzner = s.provider === "hetzner";

  const load = useCallback(async () => {
    try {
      const [sn, ev] = await Promise.all([
        serversListSnapshots(s.provider, s.id),
        serversEvents(s.provider, s.id),
      ]);
      setSnaps(sn);
      setEvents(ev);
    } catch (e) {
      setMsg(errMsg(e));
    }
  }, [s.provider, s.id]);

  useEffect(() => {
    if (open && snaps === null) void load();
  }, [open, snaps, load]);

  const doSnapshot = async () => {
    if (!label.trim()) return;
    setBusy(true);
    setMsg("");
    try {
      await serversSnapshot(s.provider, s.id, label.trim());
      setLabel("");
      setMsg("Snapshot started — it may take a few minutes to finish.");
      await load();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doRdns = async () => {
    if (!s.ipv4 || !ptr.trim()) return;
    setBusy(true);
    setMsg("");
    try {
      await serversSetRdns(s.provider, s.id, s.ipv4, ptr.trim());
      setMsg(`Reverse DNS for ${s.ipv4} set to ${ptr.trim()}.`);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doProtection = async (on: boolean) => {
    if (
      !window.confirm(
        on
          ? `Turn ON delete/rebuild protection for "${s.label}"? The provider will refuse to destroy or rebuild it until you turn this off.`
          : `Turn OFF delete/rebuild protection for "${s.label}"?`,
      )
    )
      return;
    setBusy(true);
    setMsg("");
    try {
      await serversSetProtection(s.provider, s.id, on);
      setMsg(on ? "Delete protection is now ON." : "Delete protection is now OFF.");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const doTerminal = async () => {
    if (!s.ipv4) return;
    setBusy(true);
    setMsg("");
    try {
      await serversOpenTerminal(s.ipv4);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const extras: { name: string; cmd: string }[] = [
    { name: "Netdata (live monitoring)", cmd: "curl -Ss https://get.netdata.cloud/kickstart.sh | sh" },
    {
      name: "Uptime Kuma (status page)",
      cmd: "docker run -d --restart=always -p 3001:3001 -v uptime-kuma:/app/data --name uptime-kuma louislam/uptime-kuma:1",
    },
    {
      name: "Dozzle (live Docker logs)",
      cmd: "docker run -d --name dozzle --restart=always -v /var/run/docker.sock:/var/run/docker.sock -p 8080:8080 amir20/dozzle",
    },
    { name: "fail2ban (block brute-force)", cmd: "apt-get update && apt-get install -y fail2ban && systemctl enable --now fail2ban" },
  ];

  return (
    <div className="mt-4 border-t border-[var(--border-subtle)] pt-3">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--accent)]"
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />} Manage server
      </button>

      {open && (
        <div className="mt-3 space-y-4">
          {/* Snapshots */}
          <section>
            <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
              <Camera size={13} /> Snapshots
            </div>
            <div className="flex items-center gap-2">
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Snapshot name — e.g. before-upgrade"
                className={`${inputCls} flex-1`}
              />
              <button onClick={() => void doSnapshot()} disabled={busy || !label.trim()} className={btnCls}>
                {busy ? "…" : "Snapshot"}
              </button>
            </div>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              {isHetzner
                ? "Hetzner snapshots bill ~€0.0119/GB per month until you delete them."
                : "Linode manual snapshots require the paid Backups add-on to be enabled on this Linode."}
            </p>
            {snaps && snaps.length > 0 && (
              <ul className="mt-2 space-y-1">
                {snaps.map((sn) => (
                  <li
                    key={sn.id}
                    className="flex items-center justify-between rounded-[8px] bg-[var(--bg-inset)] px-2 py-1 text-[11px]"
                  >
                    <span className="min-w-0 truncate">
                      {sn.label} <span className="text-[var(--text-muted)]">· {sn.status}</span>
                    </span>
                    <span className="shrink-0 text-[var(--text-muted)]">
                      {sn.sizeGb ? `${sn.sizeGb.toFixed(1)} GB · ` : ""}
                      {fmtWhen(sn.createdAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {snaps && snaps.length === 0 && (
              <p className="mt-1 text-[11px] text-[var(--text-muted)]">No snapshots yet.</p>
            )}
          </section>

          {/* Protection (Hetzner only) */}
          {isHetzner && (
            <section>
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
                <ShieldCheck size={13} /> Delete protection
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => void doProtection(true)} disabled={busy} className={btnCls}>
                  Enable
                </button>
                <button onClick={() => void doProtection(false)} disabled={busy} className={btnCls}>
                  Disable
                </button>
              </div>
              <p className="mt-1 text-[11px] text-[var(--text-muted)]">
                When on, Hetzner refuses to delete or rebuild this server. NorthKey can’t read the
                current setting, so choose explicitly.
              </p>
            </section>
          )}

          {/* Reverse DNS */}
          {s.ipv4 && (
            <section>
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
                <Globe size={13} /> Reverse DNS <span className="mono text-[var(--text-muted)]">({s.ipv4})</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  value={ptr}
                  onChange={(e) => setPtr(e.target.value)}
                  placeholder="PTR hostname — e.g. mail.example.com"
                  className={`${inputCls} flex-1`}
                />
                <button onClick={() => void doRdns()} disabled={busy || !ptr.trim()} className={btnCls}>
                  {busy ? "…" : "Save"}
                </button>
              </div>
            </section>
          )}

          {/* Activity */}
          <section>
            <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
              <History size={13} /> Recent activity
            </div>
            {events && events.length > 0 ? (
              <ul className="space-y-1">
                {events.slice(0, 10).map((e, i) => (
                  <li
                    key={i}
                    className="flex items-center justify-between rounded-[8px] bg-[var(--bg-inset)] px-2 py-1 text-[11px]"
                  >
                    <span className="min-w-0 truncate">
                      {e.action} <span className="text-[var(--text-muted)]">· {e.status}</span>
                    </span>
                    <span className="shrink-0 text-[var(--text-muted)]">{fmtWhen(e.createdAt)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-[var(--text-muted)]">
                {events ? "No recent activity." : "Loading…"}
              </p>
            )}
          </section>

          {/* Access */}
          {s.ipv4 && (
            <section>
              <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
                <TerminalSquare size={13} /> Access
              </div>
              <CopyLine text={`ssh root@${s.ipv4}`} />
              <button
                onClick={() => void doTerminal()}
                disabled={busy}
                className={`${btnCls} mt-2 inline-flex items-center gap-1.5`}
              >
                <TerminalSquare size={13} /> Open terminal
              </button>
              <div className="mt-3 space-y-2">
                <div className="text-[11px] text-[var(--text-muted)]">
                  One-line installs for free tools (paste into the server’s terminal):
                </div>
                {extras.map((x) => (
                  <div key={x.name}>
                    <div className="mb-0.5 text-[11px] text-[var(--text-secondary)]">{x.name}</div>
                    <CopyLine text={x.cmd} />
                  </div>
                ))}
              </div>
            </section>
          )}

          {msg && <p className="text-[11px] text-[var(--text-muted)]">{msg}</p>}
        </div>
      )}
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

/** A traffic-light tone for a metric against warn/danger thresholds (higher = worse). */
type Tone = "ok" | "warn" | "danger" | "muted";
function toneFor(v: number | undefined, warn: number, danger: number): Tone {
  if (v === undefined) return "muted";
  if (v >= danger) return "danger";
  if (v >= warn) return "warn";
  return "ok";
}
const TONE_COLOR: Record<Tone, string> = {
  ok: "var(--ok)",
  warn: "var(--warn)",
  danger: "var(--danger)",
  muted: "var(--text-muted)",
};

/** Seconds → a compact "Xd Yh" / "Yh Zm" / "Zm" uptime string. */
function fmtUptime(secs: number | undefined): string {
  if (secs === undefined || secs <= 0) return "—";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function Tile({
  label,
  value,
  sub,
  tone = "muted",
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: Tone;
}) {
  return (
    <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mono mt-0.5 text-[18px] leading-tight" style={{ color: TONE_COLOR[tone] }}>
        {value}
      </div>
      {sub && <div className="text-[10px] text-[var(--text-muted)]">{sub}</div>}
    </div>
  );
}

/** All the single-value dashboard tiles, keyed by metric kind. */
interface Tiles {
  cpu?: number;
  ram?: number;
  swap?: number;
  load?: number;
  disk?: number;
  uptime?: number;
  steal?: number;
  procs?: number;
  psi_cpu?: number;
  psi_mem?: number;
  psi_io?: number;
}

const NET_COLORS = ["#22d3ee", "#f472b6"]; // in / out
const DISK_COLORS = ["#34d399", "#fbbf24"]; // read / write
const LOAD_COLORS = ["#22d3ee", "#a78bfa", "#f472b6"]; // 1m / 5m / 15m

/** Map an aggregated multi-series result to the chart's `TimeSeries[]`, colouring by index. */
function toSeries(lines: NetdataSeriesLine[], colors: string[], scale = 1): TimeSeries[] {
  return lines.map((l, i) => ({
    label: l.label,
    color: colors[i % colors.length],
    points: scale === 1 ? l.points : l.points.map(([t, v]) => [t, v * scale] as [number, number]),
  }));
}

function NetdataLive({ s, onDisable }: { s: ManagedServer; onDisable: () => void }) {
  const [cpu, setCpu] = useState<number[]>([]);
  const [tiles, setTiles] = useState<Tiles>({});
  const [net, setNet] = useState<NetdataSeriesLine[]>([]);
  const [diskio, setDiskio] = useState<NetdataSeriesLine[]>([]);
  const [load, setLoad] = useState<NetdataSeriesLine[]>([]);
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
    // Every tile is independent: fetch in parallel, and never let one missing chart (a metric an
    // agent doesn't expose) blank the rest — allSettled + keep the last-known value.
    const tilesTick = async () => {
      const last = async (kind: string) =>
        (await netdataMetric(s.provider, s.id, host, kind, 20, 3)).at(-1)?.[1];
      const kinds: (keyof Tiles)[] = [
        "cpu", "ram", "swap", "load", "disk", "uptime", "steal", "procs", "psi_cpu", "psi_mem", "psi_io",
      ];
      const results = await Promise.allSettled(kinds.map((k) => last(k)));
      if (!alive) return;
      setTiles((prev) => {
        const next = { ...prev };
        kinds.forEach((k, i) => {
          const r = results[i];
          if (r.status === "fulfilled" && r.value !== undefined) next[k] = r.value;
        });
        return next;
      });
    };
    const chartsTick = async () => {
      const [n, d, l] = await Promise.allSettled([
        netdataSeries(s.provider, s.id, host, "net", 300, 90),
        netdataSeries(s.provider, s.id, host, "diskio", 300, 90),
        netdataSeries(s.provider, s.id, host, "load", 300, 90),
      ]);
      if (!alive) return;
      if (n.status === "fulfilled") setNet(n.value);
      if (d.status === "fulfilled") setDiskio(d.value);
      if (l.status === "fulfilled") setLoad(l.value);
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
    void tilesTick();
    void chartsTick();
    void alarmsTick();
    const t1 = window.setInterval(() => void cpuTick(), 2000);
    const t2 = window.setInterval(() => void tilesTick(), 8000);
    const t3 = window.setInterval(() => void chartsTick(), 8000);
    const t4 = window.setInterval(() => void alarmsTick(), 30000);
    return () => {
      alive = false;
      window.clearInterval(t1);
      window.clearInterval(t2);
      window.clearInterval(t3);
      window.clearInterval(t4);
    };
  }, [s.provider, s.id, host]);

  const netSeries = toSeries(net, NET_COLORS);
  // system.io is KiB/s; the throughput chart formats bytes/s → convert so the axis reads right.
  const diskSeries = toSeries(diskio, DISK_COLORS, 1024);
  const loadSeries = toSeries(load, LOAD_COLORS);

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

      {/* Tile grid — the at-a-glance health of the box. */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        <Tile label="CPU" value={fmtPct(tiles.cpu)} tone={toneFor(tiles.cpu, 75, 90)} sub="all cores" />
        <Tile label="RAM" value={fmtPct(tiles.ram)} tone={toneFor(tiles.ram, 80, 92)} />
        <Tile label="Swap" value={fmtPct(tiles.swap)} tone={toneFor(tiles.swap, 25, 60)} />
        <Tile label="Disk /" value={fmtPct(tiles.disk)} tone={toneFor(tiles.disk, 80, 92)} />
        <Tile
          label="Load 1m"
          value={tiles.load === undefined ? "—" : tiles.load.toFixed(2)}
          sub={loadSub(loadSeries)}
        />
        <Tile label="CPU steal" value={fmtPct(tiles.steal, 1)} tone={toneFor(tiles.steal, 5, 20)} sub="noisy neighbour" />
        <Tile
          label="Procs"
          value={tiles.procs === undefined ? "—" : tiles.procs.toFixed(0)}
          sub="running"
        />
        <Tile label="Uptime" value={fmtUptime(tiles.uptime)} />
        <Tile label="PSI cpu" value={fmtPct(tiles.psi_cpu, 1)} tone={toneFor(tiles.psi_cpu, 10, 40)} sub="stalled 60s" />
        <Tile label="PSI mem" value={fmtPct(tiles.psi_mem, 1)} tone={toneFor(tiles.psi_mem, 5, 20)} sub="stalled 60s" />
        <Tile label="PSI io" value={fmtPct(tiles.psi_io, 1)} tone={toneFor(tiles.psi_io, 10, 40)} sub="stalled 60s" />
      </div>

      {/* Live CPU + the two throughput charts. */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div className="mb-1 flex items-baseline justify-between text-[11px] text-[var(--text-muted)]">
            <span>CPU (per-second, live)</span>
            <span className="mono text-[var(--accent)]">{cpu.at(-1)?.toFixed(0) ?? "—"}%</span>
          </div>
          <ThroughputChart data={cpu.length ? cpu : [0, 0]} width={420} height={120} />
        </div>
        <ChartBlock title="Load average (1m · 5m · 15m)" series={loadSeries} unit="iops" />
        <ChartBlock title="Network (in · out)" series={netSeries} unit="bps" />
        <ChartBlock title="Disk I/O (read · write)" series={diskSeries} unit="bps" />
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
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

function fmtPct(v: number | undefined, digits = 0): string {
  return v === undefined ? "—" : `${v.toFixed(digits)}%`;
}

/** The "5m · 15m" companion line for the Load tile, read from the load series' last values. */
function loadSub(series: TimeSeries[]): string {
  const last = (label: string) => series.find((s) => s.label === label)?.points.at(-1)?.[1];
  const f5 = last("5m");
  const f15 = last("15m");
  if (f5 === undefined && f15 === undefined) return "";
  return `5m ${f5?.toFixed(2) ?? "—"} · 15m ${f15?.toFixed(2) ?? "—"}`;
}

/** A titled multi-series chart with a small legend; renders a placeholder until data arrives. */
function ChartBlock({ title, series, unit }: { title: string; series: TimeSeries[]; unit: "pct" | "bps" | "iops" }) {
  const hasData = series.some((s) => s.points.length >= 2);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--text-muted)]">
        <span>{title}</span>
        <span className="flex gap-2">
          {series.map((s) => (
            <span key={s.label} className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </span>
      </div>
      {hasData ? (
        <TimeSeriesChart series={series} width={420} height={120} unit={unit} />
      ) : (
        <div className="flex h-[120px] items-center justify-center rounded-[8px] bg-[var(--bg-inset)] text-[11px] text-[var(--text-muted)]">
          waiting for data…
        </div>
      )}
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
            {s.provider === "hetzner" && (
              <HetznerFirewall s={s} port={port} myIp={myIp} onOpened={() => void runProbe()} />
            )}
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

/** One-click Hetzner Cloud Firewall opener — the thing `ufw` can't fix, since a Cloud Firewall
 * sits IN FRONT of the server. Defaults to "Any IPv4" because the user's home IP changes (Starlink);
 * offer restricting to the current IP as the safer option. Read-modify-write on the backend never
 * wipes existing rules. */
function HetznerFirewall({
  s,
  port,
  myIp,
  onOpened,
}: {
  s: ManagedServer;
  port: number;
  myIp: string;
  onOpened: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [restrict, setRestrict] = useState(false);
  const ipKnown = myIp !== "<your-ip>" && myIp.trim() !== "";

  const refresh = useCallback(async () => {
    try {
      setStatus(await serversFirewallGet(s.provider, s.id));
    } catch {
      /* best-effort */
    }
  }, [s.provider, s.id]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const open = async () => {
    setBusy(true);
    setMsg("");
    try {
      const source = restrict && ipKnown ? `${myIp}/32` : "any";
      await serversFirewallAllowPort(s.provider, s.id, port, source);
      setMsg(`Opened TCP ${port} (${restrict && ipKnown ? `from ${myIp}` : "from anywhere"}). Re-checking…`);
      await refresh();
      onOpened();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <div className="space-y-2 rounded-[10px] border border-[var(--accent)]/40 bg-[var(--accent)]/10 p-2.5">
      <p className="text-[var(--text-secondary)]">
        This is a Hetzner Cloud server. If a <span className="font-medium">Hetzner Cloud Firewall</span>{" "}
        is attached, it blocks the port before <span className="mono">ufw</span> ever sees it — NorthKey
        can open it for you with the Hetzner API.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => void open()} disabled={busy} className={btnCls}>
          {busy ? "Opening…" : `Open port ${port} on the Hetzner firewall`}
        </button>
        <label className="flex items-center gap-1 text-[var(--text-muted)]" title={ipKnown ? "" : "Your IP isn't known yet"}>
          <input
            type="checkbox"
            checked={restrict && ipKnown}
            disabled={!ipKnown}
            onChange={(e) => setRestrict(e.target.checked)}
          />
          restrict to my IP ({ipKnown ? myIp : "unknown"})
        </label>
      </div>
      {!restrict && (
        <p className="text-[10px] text-[var(--text-muted)]">
          Default opens the port to any IPv4/IPv6 — the right choice when your home IP changes (Starlink).
          Anyone can reach the port, but Netdata only serves read-only metrics.
        </p>
      )}
      {msg && <p className="text-[10px] text-[var(--text-secondary)]">{msg}</p>}
      {status && (
        <div className="text-[10px] text-[var(--text-muted)]">
          {status.attached ? (
            <>
              Firewall <span className="mono">{status.firewallName}</span> ·{" "}
              {status.rules.filter((r) => r.direction === "in").length} inbound rule(s)
              {status.rules
                .filter((r) => r.direction === "in" && r.protocol === "tcp")
                .map((r) => (
                  <span key={`${r.port}-${r.ips.join(",")}`} className="mono ml-1">
                    · {r.protocol}/{r.port ?? "*"}
                  </span>
                ))}
            </>
          ) : (
            "No Hetzner firewall attached — opening a port will create and apply one."
          )}
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
