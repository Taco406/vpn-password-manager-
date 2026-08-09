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
  type ManagedServer,
  type CrowdsecStatus,
  type CrowdsecAlert,
  type CrowdsecDecision,
} from "../bridge";
import { btnCls, errMsg } from "./kit";
import { Badge } from "./ui";
import { toastError } from "./Toast";

const POLL_MS = 30_000;

export function SecurityPanel({ s }: { s: ManagedServer }) {
  const host = s.ipv4 ?? "";
  const [status, setStatus] = useState<CrowdsecStatus | null>(null);
  const [alerts, setAlerts] = useState<CrowdsecAlert[]>([]);
  const [bans, setBans] = useState<CrowdsecDecision[]>([]);
  const [deploying, setDeploying] = useState(false);
  const [deployLog, setDeployLog] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
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
        const [a, d] = await Promise.all([
          crowdsecAlerts(s.provider, s.id, host, 50),
          crowdsecDecisions(s.provider, s.id, host),
        ]);
        if (!alive.current) return;
        setAlerts(a);
        setBans(d);
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
                  <span className="ml-auto text-[var(--text-muted)]">{b.duration}</span>
                  {b.origin === "cscli" && <Badge tone="accent">manual</Badge>}
                </div>
              ))}
            </div>
          )}
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
    </div>
  );
}

function fmtTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
