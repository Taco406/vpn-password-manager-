// Fleet security summary (v0.1.72): one card on the Servers screen aggregating every
// CrowdSec-protected server — total bans, community-blocklist count, detections over the
// last 7 days, and the fleet's top attackers — so the user doesn't open three drawers.
// Data comes from the existing per-server commands; the card fans out to each protected
// server over SSH, so it loads progressively and tolerates an unreachable box.

import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldCheck, RefreshCw } from "lucide-react";
import {
  crowdsecProtectedList,
  crowdsecStatus,
  crowdsecAlerts,
  crowdsecFleetSync,
  crowdsecFleetBan,
  type ManagedServer,
  type CrowdsecAlert,
} from "../bridge";
import { btnCls, errMsg } from "./kit";
import { Card, Badge } from "./ui";
import { toastError, toastSuccess } from "./Toast";

interface PerServer {
  label: string;
  bans: number;
  community: number;
  alerts: CrowdsecAlert[];
  error?: string;
}

export function FleetSecurityCard({ servers }: { servers: ManagedServer[] }) {
  const [rows, setRows] = useState<Map<string, PerServer>>(new Map());
  const [protectedKeys, setProtectedKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [busyIp, setBusyIp] = useState("");
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const keys = await crowdsecProtectedList();
      if (!alive.current) return;
      setProtectedKeys(keys);
      const targets = servers.filter(
        (s) => s.ipv4 && keys.includes(`${s.provider}:${s.id}`),
      );
      // Fan out; each server fills in as it answers.
      await Promise.all(
        targets.map(async (s) => {
          const key = `${s.provider}:${s.id}`;
          try {
            const [st, alerts] = await Promise.all([
              crowdsecStatus(s.provider, s.id, s.ipv4 ?? ""),
              crowdsecAlerts(s.provider, s.id, s.ipv4 ?? "", 200),
            ]);
            if (!alive.current) return;
            setRows((prev) =>
              new Map(prev).set(key, {
                label: s.label,
                bans: st.activeBans,
                community: st.communityBans,
                alerts,
              }),
            );
          } catch (e) {
            if (!alive.current) return;
            setRows((prev) =>
              new Map(prev).set(key, {
                label: s.label,
                bans: 0,
                community: 0,
                alerts: [],
                error: errMsg(e),
              }),
            );
          }
        }),
      );
    } catch (e) {
      toastError(errMsg(e));
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [servers]);

  useEffect(() => {
    alive.current = true;
    void refresh();
    return () => {
      alive.current = false;
    };
    // Deliberately not re-fetching on every 60s server-list poll — Refresh is manual.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [servers.length]);

  const syncNow = async () => {
    setSyncing(true);
    try {
      const r = await crowdsecFleetSync();
      toastSuccess(
        r.propagated > 0
          ? `Shared ${r.propagated} ban(s) across ${r.servers} servers`
          : `All ${r.servers} servers already in sync`,
      );
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
    } finally {
      setSyncing(false);
    }
  };

  const banEverywhere = async (ip: string) => {
    setBusyIp(ip);
    try {
      const n = await crowdsecFleetBan(ip, 240);
      toastSuccess(`Banned ${ip} on ${n} server(s) for 4h`);
      await refresh();
    } catch (e) {
      toastError(errMsg(e));
    } finally {
      setBusyIp("");
    }
  };

  if (protectedKeys.length === 0) return null; // nothing protected yet — no card

  const data = [...rows.values()];
  const totalBans = data.reduce((a, r) => a + r.bans, 0);
  // The community blocklist is the same global list on every agent — show the max,
  // not a misleading sum.
  const community = data.reduce((a, r) => Math.max(a, r.community), 0);
  const allAlerts = data.flatMap((r) => r.alerts);
  const dayMs = 24 * 3600 * 1000;
  const now = Date.now();
  const in24h = allAlerts.filter((a) => now - Date.parse(a.createdAt) < dayMs).length;

  // 7-day buckets, oldest first.
  const days: { label: string; count: number }[] = [];
  for (let i = 6; i >= 0; i--) {
    const start = new Date(now - i * dayMs);
    const key = start.toDateString();
    days.push({
      label: start.toLocaleDateString(undefined, { weekday: "short" }),
      count: allAlerts.filter((a) => new Date(a.createdAt).toDateString() === key).length,
    });
  }
  const maxDay = Math.max(1, ...days.map((d) => d.count));

  // Fleet-wide top attackers.
  const by = new Map<string, { count: number; country: string; scenarios: Set<string> }>();
  for (const a of allAlerts) {
    if (!a.sourceIp) continue;
    const cur = by.get(a.sourceIp) ?? { count: 0, country: a.country, scenarios: new Set() };
    cur.count += 1;
    if (a.scenario) cur.scenarios.add(a.scenario);
    by.set(a.sourceIp, cur);
  }
  const top = [...by.entries()].sort((x, y) => y[1].count - x[1].count).slice(0, 5);

  return (
    <Card className="mb-3 !p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <ShieldCheck size={15} className="text-[var(--ok)]" />
        <span className="text-sm font-medium">Fleet security</span>
        <Badge tone={totalBans > 0 ? "danger" : "ok"}>{totalBans} active bans</Badge>
        <Badge tone="neutral">{in24h} detections · 24h</Badge>
        {community > 0 && (
          <span title="IPs flagged as malicious across the internet, pre-blocked by CrowdSec's community blocklist (on by default).">
            <Badge tone="accent">~{community} community-blocked</Badge>
          </span>
        )}
        <div className="ml-auto flex items-center gap-3 text-xs">
          <button
            className={btnCls}
            disabled={syncing}
            title="Push every server's bans to the others right now. Turn on 'Share bans' in the Watchdog card to do this automatically."
            onClick={() => void syncNow()}
          >
            {syncing ? "Syncing…" : "Sync bans now"}
          </button>
          <button
            onClick={() => void refresh()}
            className="inline-flex items-center gap-1 text-[var(--accent)] hover:underline"
          >
            <RefreshCw size={12} /> {loading ? "…" : "Refresh"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* 7-day trend */}
        <div>
          <div className="mb-1 text-[11px] text-[var(--text-muted)]">Detections, last 7 days</div>
          <div className="space-y-0.5">
            {days.map((d, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px]">
                <span className="w-8 text-[var(--text-muted)]">{d.label}</span>
                <div className="h-2.5 flex-1 overflow-hidden rounded bg-[var(--bg-inset)]">
                  <div
                    className="h-full rounded"
                    style={{
                      width: `${(d.count / maxDay) * 100}%`,
                      background: d.count > 0 ? "var(--warn)" : "transparent",
                    }}
                  />
                </div>
                <span className="w-6 text-right text-[var(--text-muted)]">{d.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Fleet top attackers */}
        <div>
          <div className="mb-1 text-[11px] text-[var(--text-muted)]">
            Top attackers across the fleet
          </div>
          {top.length === 0 ? (
            <p className="text-[11px] text-[var(--text-muted)]">
              Nothing recorded yet{loading ? " (loading…)" : ""}.
            </p>
          ) : (
            <div className="space-y-1">
              {top.map(([ip, t]) => (
                <div key={ip} className="flex flex-wrap items-center gap-x-2 text-[11px]">
                  <span className="mono text-[var(--text-primary)]">{ip}</span>
                  {t.country && <Badge tone="neutral">{t.country}</Badge>}
                  <span className="text-[var(--text-muted)]">×{t.count}</span>
                  <button
                    disabled={busyIp === ip}
                    onClick={() => void banEverywhere(ip)}
                    className="ml-auto text-[var(--warn)] hover:underline disabled:opacity-50"
                  >
                    ban everywhere
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Per-server strip */}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 border-t border-[var(--border-subtle)] pt-2 text-[11px] text-[var(--text-muted)]">
        {data.map((r) => (
          <span key={r.label}>
            {r.label}:{" "}
            {r.error ? (
              <span className="text-[var(--warn)]">unreachable</span>
            ) : (
              <>
                {r.bans} {r.bans === 1 ? "ban" : "bans"}
              </>
            )}
          </span>
        ))}
        {protectedKeys.length > data.length && <span>loading {protectedKeys.length - data.length} more…</span>}
      </div>
    </Card>
  );
}
