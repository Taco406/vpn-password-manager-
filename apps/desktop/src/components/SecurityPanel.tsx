// The attack-monitor (CrowdSec) panel — Phase A. Lives in the server side-panel's
// Security tab. Deploys CrowdSec to the server over SSH and shows its detection events
// and active bans. SSH brute-force + the honeypot are enforced; web-attack scenarios run
// in training mode (detect + alert, no bans) until promoted in a later phase.

import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldCheck, ShieldAlert, RefreshCw, Ban } from "lucide-react";
import {
  crowdsecDeploy,
  crowdsecStatus,
  crowdsecAlerts,
  crowdsecDecisions,
  crowdsecBan,
  crowdsecUnban,
  crowdsecScenarios,
  crowdsecPromote,
  crowdsecDemote,
  crowdsecAllowlistGet,
  crowdsecAllowlistSet,
  type ManagedServer,
  type CrowdsecStatus,
  type CrowdsecAlert,
  type CrowdsecDecision,
  type CrowdsecScenario,
} from "../bridge";
import { btnCls, inputCls, errMsg } from "./kit";
import { Badge } from "./ui";
import { toastError, toastSuccess } from "./Toast";

const POLL_MS = 30_000;

export function SecurityPanel({ s }: { s: ManagedServer }) {
  const host = s.ipv4 ?? "";
  const [status, setStatus] = useState<CrowdsecStatus | null>(null);
  const [alerts, setAlerts] = useState<CrowdsecAlert[]>([]);
  const [bans, setBans] = useState<CrowdsecDecision[]>([]);
  const [scenarios, setScenarios] = useState<CrowdsecScenario[]>([]);
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [deploying, setDeploying] = useState(false);
  const [deployLog, setDeployLog] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [busyIp, setBusyIp] = useState("");
  const [banIp, setBanIp] = useState("");
  const [newAllow, setNewAllow] = useState("");
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    if (!host) return;
    setLoading(true);
    setErr("");
    try {
      const st = await crowdsecStatus(s.provider, s.id, host);
      if (!alive.current) return;
      setStatus(st);
      if (st.protected || st.agent === "active") {
        const [a, d, sc, al] = await Promise.all([
          crowdsecAlerts(s.provider, s.id, host, 50),
          crowdsecDecisions(s.provider, s.id, host),
          crowdsecScenarios(s.provider, s.id, host).catch(() => [] as CrowdsecScenario[]),
          crowdsecAllowlistGet(s.provider, s.id, host).catch(() => [] as string[]),
        ]);
        if (!alive.current) return;
        setAlerts(a);
        setBans(d);
        setScenarios(sc);
        setAllowlist(al);
      }
    } catch (e) {
      if (alive.current) setErr(errMsg(e));
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [s.provider, s.id, host]);

  useEffect(() => {
    alive.current = true;
    void refresh();
    const t = window.setInterval(() => void refresh(), POLL_MS);
    return () => {
      alive.current = false;
      window.clearInterval(t);
    };
  }, [refresh]);

  const deploy = async () => {
    if (!host) return;
    setDeploying(true);
    setDeployLog("");
    setErr("");
    try {
      const r = await crowdsecDeploy(s.provider, s.id, host);
      setDeployLog(r.log);
      if (!r.ok) setErr("Install didn't confirm success — check the log below.");
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
      setErr(errMsg(e));
    } finally {
      setDeploying(false);
    }
  };

  const unban = async (ip: string) => {
    setBusyIp(ip);
    try {
      await crowdsecUnban(s.provider, s.id, host, ip);
      toastSuccess(`Unbanned ${ip}`);
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
    } finally {
      setBusyIp("");
    }
  };

  const ban = async (perm: boolean, ipOverride?: string) => {
    const ip = (ipOverride ?? banIp).trim();
    if (!ip) return;
    if (perm && !window.confirm(`Permanently ban ${ip}? It stays blocked until you unban it.`)) {
      return;
    }
    setBusyIp(ip);
    try {
      await crowdsecBan(s.provider, s.id, host, ip, perm ? 0 : 240); // temp = 4h
      toastSuccess(`${perm ? "Permanently banned" : "Banned"} ${ip}`);
      setBanIp("");
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
    } finally {
      setBusyIp("");
    }
  };

  const toggleScenario = async (sc: CrowdsecScenario) => {
    // Promoting to enforced can start real bans — confirm for the web scenarios.
    if (sc.simulated && !window.confirm(
      `Enforce “${sc.name}”? It will start blocking IPs that trip it. ` +
        `Make sure your allowlist covers anyone who must never be blocked.`,
    )) {
      return;
    }
    try {
      if (sc.simulated) await crowdsecPromote(s.provider, s.id, host, sc.name);
      else await crowdsecDemote(s.provider, s.id, host, sc.name);
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
    }
  };

  const addAllow = async () => {
    const ip = newAllow.trim();
    if (!ip) return;
    const next = Array.from(new Set([...allowlist, ip]));
    try {
      await crowdsecAllowlistSet(s.provider, s.id, host, next);
      setAllowlist(next);
      setNewAllow("");
      toastSuccess("Allowlist updated");
    } catch (e) {
      toastError(errMsg(e));
    }
  };

  const removeAllow = async (ip: string) => {
    const next = allowlist.filter((x) => x !== ip);
    try {
      await crowdsecAllowlistSet(s.provider, s.id, host, next);
      setAllowlist(next);
      toastSuccess("Allowlist updated");
    } catch (e) {
      toastError(errMsg(e));
    }
  };

  if (!host) {
    return (
      <p className="text-xs text-[var(--text-muted)]">
        This server has no public IPv4 address, so NorthKey can’t reach it.
      </p>
    );
  }

  const protectedOn = status?.protected || status?.agent === "active";

  return (
    <div className="space-y-4">
      <div>
        <div className="mb-1 flex items-center gap-2 text-sm font-medium">
          {protectedOn ? (
            <ShieldCheck size={15} className="text-[var(--ok)]" />
          ) : (
            <ShieldAlert size={15} className="text-[var(--text-muted)]" />
          )}
          Attack monitor
          <button
            onClick={() => void refresh()}
            className="ml-auto inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
        <p className="text-xs text-[var(--text-secondary)]">
          Installs CrowdSec on this server. It watches for attacks and blocks the attackers.
          <strong> SSH brute-force and a honeypot are enforced;</strong> web-attack detection runs
          in <strong>training mode</strong> (it logs but never blocks) so you can confirm it won’t
          catch real visitors before turning it on.
        </p>
      </div>

      {/* Status / deploy */}
      <div className="rounded-[10px] border border-[var(--border-subtle)] p-3">
        {protectedOn ? (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge tone="ok">agent {status?.agent ?? "?"}</Badge>
            <Badge tone={status?.bouncer === "active" ? "ok" : "warn"}>
              firewall {status?.bouncer ?? "?"}
            </Badge>
            <Badge tone={status && status.activeBans > 0 ? "danger" : "neutral"}>
              {status?.activeBans ?? 0} active {status?.activeBans === 1 ? "ban" : "bans"}
            </Badge>
            <button className={`${btnCls} ml-auto`} disabled={deploying} onClick={() => void deploy()}>
              {deploying ? "Updating…" : "Re-run setup"}
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-[var(--text-secondary)]">
              Not protected yet. This installs CrowdSec + a firewall bouncer over SSH (a couple of
              minutes). Your current IP is added to a never-ban allowlist automatically, so enabling
              the SSH block can’t lock you out.
            </p>
            <button className={btnCls} disabled={deploying} onClick={() => void deploy()}>
              {deploying ? "Installing… (this can take a few minutes)" : "Protect this server"}
            </button>
          </div>
        )}
        {deployLog && (
          <pre className="mono mt-2 max-h-40 overflow-auto rounded bg-[var(--bg-inset)] p-2 text-[10px] text-[var(--text-muted)]">
            {deployLog}
          </pre>
        )}
        {err && <p className="mt-2 text-[11px] text-[var(--warn)]">{err}</p>}
      </div>

      {/* Active bans */}
      {protectedOn && (
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs font-medium">
            <Ban size={13} /> Active bans ({bans.length})
          </div>
          {bans.length === 0 ? (
            <p className="text-[11px] text-[var(--text-muted)]">No IPs are currently blocked.</p>
          ) : (
            <div className="space-y-1">
              {bans.slice(0, 30).map((b) => (
                <div
                  key={b.id}
                  className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded bg-[var(--bg-inset)] px-2 py-1 text-[11px]"
                >
                  <span className="mono text-[var(--text-primary)]">{b.sourceIp}</span>
                  <span className="text-[var(--text-muted)]">{b.scenario}</span>
                  {b.origin === "cscli" && <Badge tone="accent">manual</Badge>}
                  <span className="ml-auto text-[var(--text-muted)]">{b.duration}</span>
                  <button
                    disabled={busyIp === b.sourceIp}
                    onClick={() => void unban(b.sourceIp)}
                    className="text-[var(--accent)] hover:underline disabled:opacity-50"
                  >
                    {busyIp === b.sourceIp ? "…" : "unban"}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Top attackers — who's been hitting this server, worst first */}
      {protectedOn && alerts.length > 0 && (
        <div>
          <div className="mb-1 text-xs font-medium">Top attackers</div>
          <div className="space-y-1">
            {topAttackers(alerts)
              .slice(0, 8)
              .map((at) => (
                <div
                  key={at.ip}
                  className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded bg-[var(--bg-inset)] px-2 py-1 text-[11px]"
                >
                  <span className="mono text-[var(--text-primary)]">{at.ip}</span>
                  {at.country && <Badge tone="neutral">{at.country}</Badge>}
                  <span className="text-[var(--text-muted)]">×{at.count}</span>
                  <span className="truncate text-[var(--text-secondary)]">
                    {at.scenarios.slice(0, 2).join(", ")}
                    {at.scenarios.length > 2 ? ` +${at.scenarios.length - 2}` : ""}
                  </span>
                  <span className="ml-auto text-[var(--text-muted)]">
                    last {fmtTime(at.lastSeen)}
                  </span>
                  <button
                    disabled={busyIp === at.ip}
                    onClick={() => void ban(false, at.ip)}
                    className="text-[var(--warn)] hover:underline disabled:opacity-50"
                  >
                    ban
                  </button>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Recent detections */}
      {protectedOn && (
        <div>
          <div className="mb-1 text-xs font-medium">Recent detections ({alerts.length})</div>
          {alerts.length === 0 ? (
            <p className="text-[11px] text-[var(--text-muted)]">
              Nothing seen yet{loading ? " (checking…)" : ""}. Detections appear here as they happen.
            </p>
          ) : (
            <div className="space-y-1">
              {alerts.slice(0, 60).map((a) => (
                <div
                  key={a.id}
                  className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded px-2 py-1 text-[11px] hover:bg-[var(--bg-inset)]"
                >
                  <span className="mono text-[var(--text-primary)]">{a.sourceIp || "?"}</span>
                  {a.country && <span className="text-[var(--text-muted)]">{a.country}</span>}
                  <span className="truncate text-[var(--text-secondary)]">{a.scenario}</span>
                  <span className="ml-auto text-[var(--text-muted)]">{fmtTime(a.createdAt)}</span>
                  {a.simulated ? (
                    <Badge tone="warn">training</Badge>
                  ) : (
                    <Badge tone="danger">enforced</Badge>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {/* Manual ban */}
      {protectedOn && (
        <div className="border-t border-[var(--border-subtle)] pt-3">
          <div className="mb-1 text-xs font-medium">Block an IP yourself</div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={banIp}
              onChange={(e) => setBanIp(e.target.value)}
              placeholder="1.2.3.4"
              aria-label="IP to ban"
              className={`${inputCls} !w-40`}
            />
            <button className={btnCls} disabled={!banIp.trim() || busyIp === banIp.trim()} onClick={() => void ban(false)}>
              Ban 4h
            </button>
            <button
              className={btnCls}
              disabled={!banIp.trim() || busyIp === banIp.trim()}
              onClick={() => void ban(true)}
            >
              Ban permanently
            </button>
          </div>
        </div>
      )}

      {/* Detection scenarios: training ↔ enforced */}
      {protectedOn && scenarios.length > 0 && (
        <div className="border-t border-[var(--border-subtle)] pt-3">
          <div className="mb-1 text-xs font-medium">Detection rules</div>
          <p className="mb-2 text-[11px] text-[var(--text-muted)]">
            <strong>Training</strong> rules log but never block. Promote one to <strong>enforced</strong>
            once you’ve confirmed it isn’t flagging real visitors. SSH stays enforced.
          </p>
          <div className="max-h-48 space-y-1 overflow-auto">
            {scenarios.map((sc) => (
              <div
                key={sc.name}
                className="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded px-2 py-1 text-[11px] hover:bg-[var(--bg-inset)]"
              >
                <span className="mono truncate text-[var(--text-secondary)]">{sc.name}</span>
                {sc.simulated ? (
                  <Badge tone="warn">training</Badge>
                ) : (
                  <Badge tone="ok">enforced</Badge>
                )}
                <button
                  onClick={() => void toggleScenario(sc)}
                  className="ml-auto text-[var(--accent)] hover:underline"
                >
                  {sc.simulated ? "enforce" : "back to training"}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Allowlist */}
      {protectedOn && (
        <div className="border-t border-[var(--border-subtle)] pt-3">
          <div className="mb-1 text-xs font-medium">Never-ban allowlist</div>
          <p className="mb-2 text-[11px] text-[var(--text-muted)]">
            These IPs (and private ranges) are never blocked — your own address, clients, uptime
            monitors. Your current IP was added automatically when you protected the server.
          </p>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <input
              value={newAllow}
              onChange={(e) => setNewAllow(e.target.value)}
              placeholder="1.2.3.4 or 1.2.3.0/24"
              aria-label="Allowlist entry"
              className={`${inputCls} !w-48`}
            />
            <button className={btnCls} disabled={!newAllow.trim()} onClick={() => void addAllow()}>
              Add
            </button>
          </div>
          {allowlist.length === 0 ? (
            <p className="text-[11px] text-[var(--text-muted)]">No operator IPs listed yet.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {allowlist.map((ip) => (
                <span
                  key={ip}
                  className="mono inline-flex items-center gap-1 rounded bg-[var(--bg-inset)] px-2 py-0.5 text-[11px]"
                >
                  {ip}
                  <button
                    onClick={() => void removeAllow(ip)}
                    className="text-[var(--text-muted)] hover:text-[var(--danger)]"
                    aria-label={`Remove ${ip}`}
                  >
                    ✕
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface Attacker {
  ip: string;
  country: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  scenarios: string[];
}

/** Aggregate the raw alert feed by source IP → one card per attacker, worst first. */
function topAttackers(alerts: CrowdsecAlert[]): Attacker[] {
  const by = new Map<string, Attacker>();
  for (const a of alerts) {
    if (!a.sourceIp) continue;
    const cur = by.get(a.sourceIp);
    if (cur) {
      cur.count += 1;
      if (a.country && !cur.country) cur.country = a.country;
      if (a.scenario && !cur.scenarios.includes(a.scenario)) cur.scenarios.push(a.scenario);
      if (a.createdAt < cur.firstSeen) cur.firstSeen = a.createdAt;
      if (a.createdAt > cur.lastSeen) cur.lastSeen = a.createdAt;
    } else {
      by.set(a.sourceIp, {
        ip: a.sourceIp,
        country: a.country,
        count: 1,
        firstSeen: a.createdAt,
        lastSeen: a.createdAt,
        scenarios: a.scenario ? [a.scenario] : [],
      });
    }
  }
  return [...by.values()].sort((x, y) => y.count - x.count);
}

function fmtTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
