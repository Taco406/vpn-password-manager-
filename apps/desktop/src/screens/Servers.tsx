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
  serversPortCheck,
  serversUpdatesCheck,
  serversUpdatesApply,
  type ServerUpdates,
  serversWatchdogGet,
  serversWatchdogSet,
  netdataGet,
  netdataSet,
  netdataProbe,
  netdataMetric,
  netdataSeries,
  netdataChartsIndex,
  netdataChartData,
  netdataAlarmLog,
  type NetdataChartMeta,
  type NetdataChartsIndex,
  type NetdataAlarmLogEntry,
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
import { toastError } from "../components/Toast";
import { SshTerminal } from "../components/SshTerminal";
import { SecurityPanel } from "../components/SecurityPanel";
import { TimeSeriesChart, type TimeSeries } from "../components/charts/TimeSeriesChart";
import { ThroughputChart } from "../components/charts/ThroughputChart";

const LIST_REFRESH_MS = 60_000;
const METRICS_REFRESH_MS = 60_000;

// --- Layout preferences -----------------------------------------------------
// The screen used to be a single `max-w-4xl` column of full-width cards, each of
// which expanded inline to reveal charts + Netdata + the whole lifecycle panel.
// On a 1440px+ window that wasted most of the horizontal space and pushed the
// second server below the fold. Servers now tile into a responsive grid and the
// heavy per-server panels live in a slide-over drawer instead of inline.
type Density = "comfortable" | "compact";
const DENSITY_KEY = "northkey.servers.density";
const COLS_KEY = "northkey.servers.cols";

/** Column count: "auto" tracks the window width; 1-3 pins it. */
type ColsPref = "auto" | 1 | 2 | 3;

function loadPref<T extends string | number>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return fallback;
    const n = Number(raw);
    return (Number.isFinite(n) && raw.trim() !== "" ? (n as T) : (raw as T)) ?? fallback;
  } catch {
    return fallback; // private mode / storage disabled — preferences are cosmetic
  }
}

function savePref(key: string, value: string | number) {
  try {
    window.localStorage.setItem(key, String(value));
  } catch {
    /* cosmetic only */
  }
}

function gridCls(cols: ColsPref): string {
  if (cols === 1) return "grid grid-cols-1 gap-3";
  if (cols === 2) return "grid grid-cols-1 gap-3 lg:grid-cols-2";
  if (cols === 3) return "grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3";
  return "grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3 min-[2100px]:grid-cols-4";
}

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
  // Drawer target is stored as "provider:id" rather than the object so the row keeps
  // pointing at the freshly-polled server after each 60s refresh replaces the array.
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [density, setDensity] = useState<Density>(() => loadPref<Density>(DENSITY_KEY, "comfortable"));
  const [cols, setCols] = useState<ColsPref>(() => loadPref<ColsPref>(COLS_KEY, "auto"));
  const [query, setQuery] = useState("");

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

  const q = query.trim().toLowerCase();
  const shown = q
    ? servers.filter(
        (s) =>
          s.label.toLowerCase().includes(q) ||
          (s.ipv4 ?? "").includes(q) ||
          s.region.toLowerCase().includes(q) ||
          s.provider.toLowerCase().includes(q) ||
          s.roles.some((r) => r.toLowerCase().includes(q)),
      )
    : servers;
  const openServer = openKey ? servers.find((s) => `${s.provider}:${s.id}` === openKey) ?? null : null;

  return (
    <div className="mx-auto max-w-[1800px] px-6 py-8 xl:px-8">
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
              <div className="ml-auto flex items-center gap-3">
                {servers.length > 3 && (
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Filter…"
                    aria-label="Filter servers"
                    className={`${inputCls} !h-7 !w-36 !py-0 text-xs`}
                  />
                )}
                {/* Layout controls: the window is the same width for everyone, but how
                    many servers fit comfortably is a taste call — so it's a preference. */}
                <div className="flex items-center gap-1" role="group" aria-label="Card density">
                  {(["comfortable", "compact"] as Density[]).map((d) => (
                    <button
                      key={d}
                      onClick={() => {
                        setDensity(d);
                        savePref(DENSITY_KEY, d);
                      }}
                      aria-pressed={density === d}
                      className={`rounded px-1.5 py-0.5 text-[11px] ${
                        density === d
                          ? "bg-[var(--accent)]/15 text-[var(--accent)]"
                          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      {d === "comfortable" ? "Roomy" : "Dense"}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-1" role="group" aria-label="Columns">
                  {(["auto", 1, 2, 3] as ColsPref[]).map((c) => (
                    <button
                      key={String(c)}
                      onClick={() => {
                        setCols(c);
                        savePref(COLS_KEY, c);
                      }}
                      aria-pressed={cols === c}
                      className={`rounded px-1.5 py-0.5 text-[11px] ${
                        cols === c
                          ? "bg-[var(--accent)]/15 text-[var(--accent)]"
                          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      {c === "auto" ? "Auto" : c}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => void refresh()}
                  className="inline-flex items-center gap-1 text-[var(--accent)] hover:underline"
                >
                  <RefreshCw size={12} /> Refresh
                </button>
              </div>
            </div>
          </Card>

          {provErrors.map((e) => (
            <Card key={e.provider} className="mb-4 border border-[var(--warn)]/40">
              <p className="text-xs text-[var(--warn)]">
                {e.provider}: {e.message}
              </p>
            </Card>
          ))}

          <div className={gridCls(cols)}>
            {shown.map((s) => (
              <ServerCard
                key={`${s.provider}:${s.id}`}
                s={s}
                busy={busy}
                density={density}
                onAct={act}
                onOpen={() => setOpenKey(`${s.provider}:${s.id}`)}
              />
            ))}
          </div>

          {shown.length === 0 && servers.length > 0 && (
            <Card>
              <p className="text-xs text-[var(--text-muted)]">No server matches “{query}”.</p>
            </Card>
          )}

          {servers.length === 0 && provErrors.length === 0 && (
            <Card>
              <p className="text-xs text-[var(--text-muted)]">No servers found on your accounts.</p>
            </Card>
          )}

          {/* Fleet-wide panels sit below the grid, side by side on wide windows. */}
          <div className="mt-4 grid grid-cols-1 gap-3 2xl:grid-cols-2">
            <WatchdogCard />
            <AlertFeed />
          </div>
        </>
      )}

      {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}

      {openServer && <ServerDrawer s={openServer} busy={busy} onAct={act} onClose={() => setOpenKey(null)} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Slide-over drawer: everything that used to expand inline (provider charts,
// Netdata, and the whole lifecycle/"Manage server" panel) now lives here, so a
// server's detail never pushes its neighbours off the screen.
// ---------------------------------------------------------------------------
type DrawerTab = "overview" | "monitoring" | "security" | "manage" | "access";

function ServerDrawer({
  s,
  busy,
  onAct,
  onClose,
}: {
  s: ManagedServer;
  busy: boolean;
  onAct: (s: ManagedServer, action: "start" | "stop" | "reboot") => Promise<void>;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<DrawerTab>("overview");

  // Esc closes, matching every other dismissible surface in the app.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const TABS: { id: DrawerTab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "monitoring", label: "Monitoring" },
    { id: "security", label: "Security" },
    { id: "manage", label: "Manage" },
    { id: "access", label: "Access" },
  ];

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <button
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0 bg-black/50 backdrop-blur-[1px]"
      />
      <aside
        role="dialog"
        aria-label={`${s.label} details`}
        className="relative flex h-full w-full max-w-[900px] flex-col overflow-hidden border-l border-[var(--border-subtle)] bg-[var(--bg-base)] shadow-2xl"
      >
        <header className="shrink-0 border-b border-[var(--border-subtle)] px-5 py-3">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{s.label}</span>
            <Badge tone={s.provider === "hetzner" ? "danger" : "accent"}>
              {s.provider === "hetzner" ? "Hetzner" : "Linode"}
            </Badge>
            <Badge tone={stateTone(s.state)}>{s.state}</Badge>
            <button
              onClick={onClose}
              className="ml-auto text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            >
              Close ✕
            </button>
          </div>
          <div className="mt-2 flex gap-1">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                aria-pressed={tab === t.id}
                className={`rounded px-2.5 py-1 text-xs ${
                  tab === t.id
                    ? "bg-[var(--accent)]/15 text-[var(--accent)]"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {tab === "overview" && <DrawerOverview s={s} busy={busy} onAct={onAct} />}
          {tab === "monitoring" && (s.ipv4 ? <NetdataPanel s={s} /> : <NoIp />)}
          {tab === "security" && (s.ipv4 ? <SecurityPanel s={s} /> : <NoIp />)}
          {tab === "manage" && (
            <>
              {s.ipv4 && <UpdatesCard s={s} />}
              <ServerLifecycle s={s} />
            </>
          )}
          {tab === "access" && (s.ipv4 ? <AccessTab s={s} /> : <NoIp />)}
        </div>
      </aside>
    </div>
  );
}

function NoIp() {
  return (
    <p className="text-xs text-[var(--text-muted)]">
      This server has no public IPv4 address, so the app can’t reach it directly.
    </p>
  );
}

/**
 * System updates over SSH (v0.1.69): what's pending, whether the package manager is
 * genuinely busy right now, whether a restart is needed — and one click to install.
 * Built after the attack-monitor deploy kept guessing at "busy": this shows the truth.
 */
function UpdatesCard({ s }: { s: ManagedServer }) {
  const host = s.ipv4 ?? "";
  const [info, setInfo] = useState<ServerUpdates | null>(null);
  const [checking, setChecking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [log, setLog] = useState("");
  const [err, setErr] = useState("");

  const check = useCallback(async () => {
    if (!host) return;
    setChecking(true);
    setErr("");
    try {
      setInfo(await serversUpdatesCheck(s.provider, s.id, host));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setChecking(false);
    }
  }, [s.provider, s.id, host]);

  useEffect(() => {
    void check();
  }, [check]);

  const apply = async () => {
    if (
      !window.confirm(
        "Install system updates on this server now? Services on it may restart briefly.",
      )
    ) {
      return;
    }
    setApplying(true);
    setErr("");
    setLog("");
    try {
      const r = await serversUpdatesApply(s.provider, s.id, host);
      setLog(r.log);
      if (!r.ok) setErr("The update didn’t finish cleanly — see the log below.");
      await check();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="mb-4 rounded-[10px] border border-[var(--border-subtle)] p-3">
      <div className="mb-1 flex items-center gap-2 text-sm font-medium">
        System updates
        <button
          onClick={() => void check()}
          className="ml-auto inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
        >
          <RefreshCw size={12} /> {checking ? "Checking…" : "Check again"}
        </button>
      </div>

      {!info && checking && (
        <p className="text-[11px] text-[var(--text-muted)]">Asking the server…</p>
      )}
      {!info && err && <p className="text-[11px] text-[var(--warn)]">{err}</p>}

      {info && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {info.locked && <Badge tone="warn">package manager busy right now</Badge>}
            <Badge tone={info.pending > 0 ? "warn" : "ok"}>
              {info.pending === 0 ? "up to date" : `${info.pending} updates available`}
            </Badge>
            {info.security > 0 && <Badge tone="danger">{info.security} security</Badge>}
            {info.rebootRequired && <Badge tone="warn">restart needed to finish</Badge>}
          </div>
          {info.packages.length > 0 && (
            <p className="mono mt-1 truncate text-[11px] text-[var(--text-muted)]">
              {info.packages.slice(0, 8).join(", ")}
              {info.pending > 8 ? ` +${info.pending - 8} more` : ""}
            </p>
          )}
          <div className="mt-2 flex items-center gap-3">
            {info.pending > 0 && (
              <button className={btnCls} disabled={applying || info.locked} onClick={() => void apply()}>
                {applying ? "Installing… (this can take several minutes)" : `Install ${info.pending} updates`}
              </button>
            )}
            {info.rebootRequired && (
              <span className="text-[11px] text-[var(--text-muted)]">
                Use the Reboot button on the server card when convenient.
              </span>
            )}
          </div>
          {err && info && <p className="mt-2 text-[11px] text-[var(--warn)]">{err}</p>}
          {log && (
            <pre className="mono mt-2 max-h-40 overflow-auto rounded bg-[var(--bg-inset)] p-2 text-[10px] text-[var(--text-muted)]">
              {log}
            </pre>
          )}
        </>
      )}
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

/**
 * One tile in the server grid. Deliberately fixed-height and self-contained: it
 * shows identity, health at a glance and the power controls, and defers every
 * heavy panel to the drawer. Nothing here expands, so cards stay aligned.
 */
function ServerCard({
  s,
  busy,
  density,
  onAct,
  onOpen,
}: {
  s: ManagedServer;
  busy: boolean;
  density: Density;
  onAct: (s: ManagedServer, action: "start" | "stop" | "reboot") => Promise<void>;
  onOpen: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const roomy = density === "comfortable";

  const copyIp = async () => {
    if (!s.ipv4) return;
    await navigator.clipboard?.writeText(s.ipv4);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <Card className={roomy ? "!p-4" : "!p-3"}>
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={onOpen}
              className="truncate text-sm font-medium hover:text-[var(--accent)]"
              title="Open details"
            >
              {s.label}
            </button>
            <Badge tone={s.provider === "hetzner" ? "danger" : "accent"}>
              {s.provider === "hetzner" ? "Hetzner" : "Linode"}
            </Badge>
            <Badge tone={stateTone(s.state)}>{s.state}</Badge>
            {s.roles
              .filter((r) => r !== "external")
              .map((r) => (
                <Badge key={r} tone={roleTone(r)}>
                  {r}
                </Badge>
              ))}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px] text-[var(--text-muted)]">
            <span className="mono">{s.region}</span>
            {s.vcpus > 0 && (
              <span>
                {s.vcpus} vCPU · {(s.memoryMb / 1024).toFixed(0)} GB
              </span>
            )}
            <span>
              {s.currency === "EUR" ? "€" : "$"}
              {s.monthly.toFixed(2)}/mo
            </span>
          </div>
          {s.ipv4 && (
            <button
              onClick={() => void copyIp()}
              className="mono mt-0.5 inline-flex items-center gap-1 text-[11px] text-[var(--text-muted)] hover:text-[var(--accent)]"
            >
              {s.ipv4} <CopyIcon size={10} />
              {copied && <span className="text-[var(--ok)]">copied</span>}
            </button>
          )}
        </div>
      </div>

      {roomy && s.ipv4 && <CardVitals s={s} />}

      <div className="mt-3 flex items-center gap-3 border-t border-[var(--border-subtle)] pt-2 text-xs">
        {s.state === "stopped" ? (
          <button
            disabled={busy}
            onClick={() => void onAct(s, "start")}
            className="text-[var(--ok)] hover:underline disabled:opacity-50"
          >
            Start
          </button>
        ) : (
          <button
            disabled={busy}
            onClick={() => void onAct(s, "stop")}
            className="text-[var(--text-secondary)] hover:underline disabled:opacity-50"
          >
            Stop
          </button>
        )}
        <button
          disabled={busy || s.state === "stopped"}
          onClick={() => void onAct(s, "reboot")}
          className="text-[var(--accent)] hover:underline disabled:opacity-50"
        >
          Reboot
        </button>
        <button onClick={onOpen} className="ml-auto text-[var(--accent)] hover:underline">
          Details →
        </button>
      </div>
    </Card>
  );
}

/**
 * At-a-glance CPU/RAM for a card. Reuses the existing Netdata metric command, so
 * it only shows anything for servers whose agent is already reachable — a server
 * that isn't set up simply shows nothing rather than an error, because the card
 * is not where you'd fix that (the drawer's Monitoring tab is).
 */
function CardVitals({ s }: { s: ManagedServer }) {
  const [cpu, setCpu] = useState<number | undefined>();
  const [ram, setRam] = useState<number | undefined>();
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    const last = (pts: [number, number][]): number | undefined =>
      pts.length ? pts[pts.length - 1][1] : undefined;
    const load = async () => {
      try {
        const cfg = await netdataGet(s.provider, s.id);
        if (!cfg.enabled || !s.ipv4) return;
        // Two points over the last minute is the cheapest query that still yields a
        // current reading; the drawer owns the real time-series views.
        const [c, r] = await Promise.all([
          netdataMetric(s.provider, s.id, s.ipv4, "cpu", 60, 2),
          netdataMetric(s.provider, s.id, s.ipv4, "ram", 60, 2),
        ]);
        if (!alive.current) return;
        setCpu(last(c));
        setRam(last(r));
      } catch {
        /* card vitals are decorative — the Monitoring tab reports real errors */
      }
    };
    void load();
    const t = window.setInterval(() => void load(), METRICS_REFRESH_MS);
    return () => {
      alive.current = false;
      window.clearInterval(t);
    };
  }, [s.provider, s.id, s.ipv4]);

  if (cpu === undefined && ram === undefined) return null;
  return (
    <div className="mt-2 grid grid-cols-2 gap-2">
      <MiniStat label="CPU" pct={cpu} />
      <MiniStat label="RAM" pct={ram} />
    </div>
  );
}

function MiniStat({ label, pct }: { label: string; pct: number | undefined }) {
  const v = pct ?? 0;
  const tone = v >= 90 ? "var(--danger)" : v >= 70 ? "var(--warn)" : "var(--ok)";
  return (
    <div>
      <div className="flex items-baseline justify-between text-[10px] text-[var(--text-muted)]">
        <span>{label}</span>
        <span className="mono" style={{ color: tone }}>
          {pct === undefined ? "—" : `${v.toFixed(0)}%`}
        </span>
      </div>
      <div className="mt-0.5 h-1 overflow-hidden rounded bg-[var(--bg-inset)]">
        <div className="h-full rounded" style={{ width: `${Math.min(100, v)}%`, background: tone }} />
      </div>
    </div>
  );
}

/** Drawer tab 1: provider-side charts + power, i.e. what the old inline expand showed first. */
function DrawerOverview({
  s,
  busy,
  onAct,
}: {
  s: ManagedServer;
  busy: boolean;
  onAct: (s: ManagedServer, action: "start" | "stop" | "reboot") => Promise<void>;
}) {
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[var(--text-muted)]">
        <span className="mono">{s.instanceType}</span>
        {s.vcpus > 0 && (
          <span>
            {s.vcpus} vCPU · {(s.memoryMb / 1024).toFixed(0)} GB RAM · {s.diskGb} GB disk
          </span>
        )}
        <span className="mono">{s.region}</span>
        <div className="ml-auto flex items-center gap-3 text-xs">
          {s.state === "stopped" ? (
            <button
              disabled={busy}
              onClick={() => void onAct(s, "start")}
              className="text-[var(--ok)] hover:underline disabled:opacity-50"
            >
              Start
            </button>
          ) : (
            <button
              disabled={busy}
              onClick={() => void onAct(s, "stop")}
              className="text-[var(--text-secondary)] hover:underline disabled:opacity-50"
            >
              Stop
            </button>
          )}
          <button
            disabled={busy || s.state === "stopped"}
            onClick={() => void onAct(s, "reboot")}
            className="text-[var(--accent)] hover:underline disabled:opacity-50"
          >
            Reboot
          </button>
        </div>
      </div>
      <ServerCharts s={s} />
    </>
  );
}

/**
 * Drawer tab 4: reaching the box. The port checker exists because diagnosing
 * "monitoring won't connect" previously meant SSH-ing in and running five
 * commands; a host-side firewall (ufw) is invisible from the provider console,
 * and a refused-vs-timeout distinction identifies it immediately.
 */
function AccessTab({ s }: { s: ManagedServer }) {
  const host = s.ipv4 ?? "";
  const [port, setPort] = useState(19999);
  const [probing, setProbing] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; detail: string } | null>(null);

  const COMMON: { port: number; what: string }[] = [
    { port: 22, what: "SSH" },
    { port: 80, what: "HTTP" },
    { port: 443, what: "HTTPS" },
    { port: 19999, what: "Netdata" },
  ];

  const check = async (p: number) => {
    setPort(p);
    setProbing(true);
    setResult(null);
    try {
      const r = await serversPortCheck(host, p);
      setResult({ ok: r.open, detail: r.detail });
    } catch (e) {
      setResult({ ok: false, detail: errMsg(e) });
    }
    setProbing(false);
  };

  return (
    <div className="space-y-4">
      <SshTerminal s={s} />

      <div className="border-t border-[var(--border-subtle)] pt-3">
        <div className="mb-1 flex items-center gap-2 text-sm font-medium">
          <TerminalSquare size={14} /> Open a separate terminal
        </div>
        <p className="mb-2 text-xs text-[var(--text-secondary)]">
          Prefer your own terminal app? This opens your system terminal connected to this server.
        </p>
        <button className={btnCls} onClick={() => void serversOpenTerminal(host)}>
          SSH to {host}
        </button>
        <div className="mt-2">
          <CopyLine text={`ssh root@${host}`} />
        </div>
      </div>

      <div className="border-t border-[var(--border-subtle)] pt-3">
        <div className="mb-1 flex items-center gap-2 text-sm font-medium">
          <ShieldCheck size={14} /> Can I reach a port?
        </div>
        <p className="mb-2 text-xs text-[var(--text-secondary)]">
          Tests from this computer, so it sees exactly what the app sees — including any firewall
          running <em>on</em> the server that your provider’s console doesn’t show.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {COMMON.map((c) => (
            <button key={c.port} className={btnCls} disabled={probing} onClick={() => void check(c.port)}>
              {c.what} ({c.port})
            </button>
          ))}
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(Number(e.target.value))}
            aria-label="Port to test"
            className={`${inputCls} !w-24`}
          />
          <button className={btnCls} disabled={probing} onClick={() => void check(port)}>
            {probing ? "Testing…" : "Test"}
          </button>
        </div>
        {result && (
          <div
            className={`mt-2 rounded-[10px] border p-2 text-xs ${
              result.ok
                ? "border-[var(--ok)]/40 bg-[var(--ok)]/10 text-[var(--ok)]"
                : "border-[var(--warn)]/40 bg-[var(--warn)]/10 text-[var(--warn)]"
            }`}
          >
            {result.detail}
          </div>
        )}
      </div>
    </div>
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
        const m = await serversMetrics(s.provider, s.id, windowSecs, s.vcpus ?? 0);
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
            <div className="mb-1 text-[11px] text-[var(--text-muted)]">CPU (% of all cores)</div>
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
  const [alertLog, setAlertLog] = useState<NetdataAlarmLogEntry[]>([]);
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
      try {
        const l = await netdataAlarmLog(s.provider, s.id, host);
        if (alive) setAlertLog(l);
      } catch {
        /* best-effort — older agents may not expose the log */
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

      {alertLog.length > 0 && <RecentAlerts entries={alertLog} />}

      <NetdataExplorer s={s} host={host} />
    </div>
  );
}

/** The last 24h of alarm transitions — what fired AND what cleared, with times. */
function RecentAlerts({ entries }: { entries: NetdataAlarmLogEntry[] }) {
  const [open, setOpen] = useState(false);
  const fmtWhen = (ts: number) =>
    new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const toneOf = (status: string): Tone =>
    status === "CRITICAL" ? "danger" : status === "WARNING" ? "warn" : "ok";
  return (
    <div className="mt-4">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        Recent alerts ({entries.length} in 24h)
      </button>
      {open && (
        <div className="mt-2 max-h-48 overflow-y-auto rounded-[8px] border border-[var(--border-subtle)]">
          {entries.map((e, i) => (
            <div key={i} className="flex items-baseline gap-2 px-2 py-1 text-[11px]">
              <span className="mono text-[var(--text-muted)]">{fmtWhen(e.when)}</span>
              <span className="min-w-0 flex-1 truncate">{e.name}</span>
              <span style={{ color: TONE_COLOR[toneOf(e.status)] }}>
                {e.oldStatus} → {e.status}
              </span>
              {e.value && <span className="mono text-[var(--text-muted)]">{e.value}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- Containers + the all-charts browser (v0.1.61) --------------------------
// One index fetch powers both: every Docker/cgroup container gets its own live card, and the
// browser makes EVERY chart the agent exposes reachable — per-disk, per-interface, per-service,
// apps.* — instead of only the fixed system.* set above.

const CONTAINER_COLORS = ["#22d3ee", "#f472b6", "#a78bfa", "#34d399", "#fbbf24"];

function NetdataExplorer({ s, host }: { s: ManagedServer; host: string }) {
  const [index, setIndex] = useState<NetdataChartsIndex | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const idx = await netdataChartsIndex(s.provider, s.id, host);
        if (alive) {
          setIndex(idx);
          setErr("");
        }
      } catch (e) {
        if (alive) setErr(errMsg(e));
      }
    };
    void tick();
    const t = window.setInterval(() => void tick(), 60_000); // containers come and go with deploys
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [s.provider, s.id, host]);

  if (err) {
    return <p className="mt-3 text-[11px] text-[var(--text-muted)]">Chart index unavailable: {err}</p>;
  }
  if (!index) return null;
  return (
    <div>
      {index.containers.length > 0 && (
        <div className="mt-4">
          <div className="mb-2 text-[11px] font-medium text-[var(--text-secondary)]">
            Containers ({index.containers.length})
          </div>
          <div className="space-y-2">
            {index.containers.map((name) => (
              <ContainerRow key={name} s={s} host={host} name={name} />
            ))}
          </div>
        </div>
      )}
      {CHART_GROUPS.map((g) => {
        const charts = index.charts.filter(g.match);
        return charts.length > 0 ? (
          <ChartGroup key={g.key} s={s} host={host} title={g.label} charts={charts} />
        ) : null;
      })}
      <ChartBrowser s={s} host={host} charts={index.charts} />
    </div>
  );
}

// Curated slices of the index — the metrics people actually go looking for, one collapsible
// group each, without having to know Netdata's chart-id naming.
const CHART_GROUPS: { key: string; label: string; match: (c: NetdataChartMeta) => boolean }[] = [
  {
    key: "disks",
    label: "Disks",
    match: (c) => c.id.startsWith("disk_space.") || c.id.startsWith("disk."),
  },
  { key: "ifaces", label: "Network interfaces", match: (c) => c.id.startsWith("net.") },
  {
    key: "services",
    label: "Services",
    match: (c) => c.id.startsWith("systemd_service") || c.id.startsWith("services."),
  },
];

/** A collapsible curated group: pick a chart from the list, it renders live below. */
function ChartGroup({
  s,
  host,
  title,
  charts,
}: {
  s: ManagedServer;
  host: string;
  title: string;
  charts: NetdataChartMeta[];
}) {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<NetdataChartMeta | null>(null);
  return (
    <div className="mt-4">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {title} ({charts.length})
      </button>
      {open && (
        <div className="mt-2">
          <div className="max-h-40 overflow-y-auto rounded-[8px] border border-[var(--border-subtle)]">
            {charts.map((c) => (
              <button
                key={c.id}
                onClick={() => setSel(c)}
                className={`flex w-full items-baseline gap-2 px-2 py-1 text-left text-[11px] hover:bg-[var(--bg-inset)] ${sel?.id === c.id ? "bg-[var(--bg-inset)]" : ""}`}
              >
                <span className="mono">{c.id}</span>
                <span className="min-w-0 flex-1 truncate text-[var(--text-muted)]">{c.title}</span>
                <span className="text-[var(--text-muted)]">{c.units}</span>
              </button>
            ))}
          </div>
          {sel && (
            <div className="mt-3">
              <LiveChart s={s} host={host} meta={sel} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** One chart by id, polled live, every dimension under the agent's own label. */
function LiveChart({ s, host, meta }: { s: ManagedServer; host: string; meta: NetdataChartMeta }) {
  const [lines, setLines] = useState<NetdataSeriesLine[]>([]);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const l = await netdataChartData(s.provider, s.id, host, meta.id, 300, 90);
        if (alive) setLines(l);
      } catch {
        if (alive) setLines([]);
      }
    };
    setLines([]);
    void tick();
    const t = window.setInterval(() => void tick(), 8000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [s.provider, s.id, host, meta.id]);
  return (
    <ChartBlock
      title={`${meta.id} — ${meta.title}${meta.units ? ` (${meta.units})` : ""}`}
      series={toSeries(lines, CONTAINER_COLORS)}
      unit="iops"
    />
  );
}

/** One container's live vitals: current CPU + memory, expandable to full charts. */
function ContainerRow({ s, host, name }: { s: ManagedServer; host: string; name: string }) {
  const [open, setOpen] = useState(false);
  const [cpu, setCpu] = useState<NetdataSeriesLine[]>([]);
  const [mem, setMem] = useState<NetdataSeriesLine[]>([]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const [c, m] = await Promise.allSettled([
        netdataChartData(s.provider, s.id, host, `cgroup_${name}.cpu`, 300, 60),
        netdataChartData(s.provider, s.id, host, `cgroup_${name}.mem`, 300, 60),
      ]);
      if (!alive) return;
      if (c.status === "fulfilled") setCpu(c.value);
      if (m.status === "fulfilled") setMem(m.value);
    };
    void tick();
    const t = window.setInterval(() => void tick(), 10_000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [s.provider, s.id, host, name]);

  // Current CPU % = sum of the chart's dimensions' latest values; memory = summed MiB.
  const lastSum = (lines: NetdataSeriesLine[]) =>
    lines.reduce((acc, l) => acc + (l.points.at(-1)?.[1] ?? 0), 0);
  const cpuNow = cpu.length ? lastSum(cpu) : undefined;
  const memNow = mem.length ? lastSum(mem) : undefined;

  return (
    <div className="rounded-[8px] bg-[var(--bg-inset)] px-2.5 py-1.5">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 text-left">
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span className="mono min-w-0 flex-1 truncate text-xs">{name}</span>
        <span className="mono text-[11px]" style={{ color: TONE_COLOR[toneFor(cpuNow, 75, 90)] }}>
          {cpuNow === undefined ? "—" : `${cpuNow.toFixed(1)}%`}
        </span>
        <span className="mono w-20 text-right text-[11px] text-[var(--text-muted)]">
          {memNow === undefined ? "—" : fmtMiB(memNow)}
        </span>
      </button>
      {open && (
        <div className="mt-2 grid gap-4 lg:grid-cols-2">
          <ChartBlock title="CPU (%)" series={toSeries(cpu, CONTAINER_COLORS)} unit="pct" />
          <ChartBlock title="Memory (MiB)" series={toSeries(mem, CONTAINER_COLORS)} unit="iops" />
        </div>
      )}
    </div>
  );
}

/** MiB → a compact human string (Netdata cgroup mem charts report MiB). */
function fmtMiB(mib: number): string {
  return mib >= 1024 ? `${(mib / 1024).toFixed(1)} GiB` : `${mib.toFixed(0)} MiB`;
}

/** Search-and-render for EVERY chart the agent exposes. */
function ChartBrowser({
  s,
  host,
  charts,
}: {
  s: ManagedServer;
  host: string;
  charts: NetdataChartMeta[];
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<NetdataChartMeta | null>(null);

  const needle = q.trim().toLowerCase();
  const matches = needle
    ? charts
        .filter(
          (c) =>
            c.id.toLowerCase().includes(needle) ||
            c.title.toLowerCase().includes(needle) ||
            c.family.toLowerCase().includes(needle),
        )
        .slice(0, 12)
    : [];

  return (
    <div className="mt-4">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        All charts ({charts.length})
      </button>
      {open && (
        <div className="mt-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search every metric this agent has — disk, docker, systemd, app…"
            className={`${inputCls} w-full text-xs`}
          />
          {matches.length > 0 && (
            <div className="mt-1 max-h-48 overflow-y-auto rounded-[8px] border border-[var(--border-subtle)]">
              {matches.map((c) => (
                <button
                  key={c.id}
                  onClick={() => {
                    setSel(c);
                    setQ("");
                  }}
                  className="flex w-full items-baseline gap-2 px-2 py-1 text-left text-[11px] hover:bg-[var(--bg-inset)]"
                >
                  <span className="mono">{c.id}</span>
                  <span className="min-w-0 flex-1 truncate text-[var(--text-muted)]">{c.title}</span>
                  <span className="text-[var(--text-muted)]">{c.units}</span>
                </button>
              ))}
            </div>
          )}
          {sel && (
            <div className="mt-3">
              <LiveChart s={s} host={host} meta={sel} />
            </div>
          )}
        </div>
      )}
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
    serversWatchdogSet(next)
      .then(() => {
        setSaved(true);
        window.setTimeout(() => setSaved(false), 1200);
      })
      .catch((e) => {
        toastError(e);
        setCfg(cfg); // revert the toggle to what actually persisted
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
        <div className="mt-2">
          <Toggle
            label="Alert me about attacks (new blocks on protected servers)"
            checked={cfg.securityAlerts}
            onChange={(v) => patch({ securityAlerts: v })}
          />
          <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">
            Checks each CrowdSec-protected server for new bans each round (makes a background SSH
            connection). Set up protection from a server’s Security tab first.
          </p>
        </div>
      )}
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
