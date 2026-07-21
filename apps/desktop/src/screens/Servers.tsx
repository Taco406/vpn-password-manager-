// The Servers screen: every server the user owns — all Linode instances (including
// NorthKey's own VPN/sync nodes, labeled by role) and all Hetzner Cloud servers — with
// power actions and real utilization graphs from the provider metrics APIs.

import { useCallback, useEffect, useRef, useState } from "react";
import { Server, RefreshCw, Copy as CopyIcon, ChevronDown, ChevronRight } from "lucide-react";
import {
  serversConfig,
  serversList,
  serversMetrics,
  serversPower,
  type ManagedServer,
  type ServerMetricsOut,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { errMsg } from "../components/kit";
import { TimeSeriesChart } from "../components/charts/TimeSeriesChart";

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
    </div>
  );
}
