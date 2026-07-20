import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Power, Zap, Cpu, MemoryStick, Activity, DollarSign, Gauge, Cloud } from "lucide-react";
import type { InstanceType, Region } from "@sentinel/shared";
import {
  bridge,
  vpnRealEnabled,
  vpnNodes,
  vpnCostSummary,
  vpnNodeAction,
  vpnNodesDestroyAll,
  type VpnNode,
  type VpnCostSummary,
} from "../bridge";
import { useApp } from "../stores/app";
import { Globe } from "../components/globe/Globe";
import { ThroughputChart, fmtRate, fmtBytes } from "../components/charts/ThroughputChart";
import { Card, Button, Badge } from "../components/ui";
import { errMsg, btnCls } from "../components/kit";

export function Vpn() {
  const [regions, setRegions] = useState<Region[]>([]);
  const [types, setTypes] = useState<InstanceType[]>([]);
  const [selectedRegion, setSelectedRegion] = useState<string>("us-east");
  const [selectedType, setSelectedType] = useState<string>("g6-nanode-1");
  const [cost, setCost] = useState<{ hourlyUsd: number; accruedUsd: number }>({ hourlyUsd: 0, accruedUsd: 0 });
  const connect = useApp((s) => s.connect);
  const metrics = useApp((s) => s.metrics);
  const rxHistory = useApp((s) => s.rxHistory);

  useEffect(() => {
    void bridge.vpnRegions().then(setRegions);
    void bridge.vpnInstanceTypes().then(setTypes);
    // Demo/screenshot: auto-connect when asked via the window query.
    const q = new URLSearchParams(window.location.search);
    if (q.get("vpn") === "connected") {
      const region = q.get("region") ?? "eu-central";
      setSelectedRegion(region);
      void bridge.vpnConnect(region, "g6-nanode-1");
    }
  }, []);

  useEffect(() => {
    const poll = () => bridge.vpnCostEstimate().then(setCost);
    void poll();
    const frozen = document.documentElement.getAttribute("data-freeze") === "1";
    if (frozen) return;
    const t = setInterval(poll, 2000);
    return () => clearInterval(t);
  }, [connect.stage]);

  const stage: "idle" | "connecting" | "connected" =
    connect.stage === "idle" ? "idle" : connect.stage === "connected" ? "connected" : "connecting";
  const busy = stage === "connecting";

  const doConnect = () => bridge.vpnConnect(selectedRegion, selectedType);
  const doDisconnect = () => bridge.vpnDisconnect();

  const down = fmtRate(metrics?.rx ?? 0);
  const up = fmtRate(metrics?.tx ?? 0);

  return (
    <div className="grid h-full grid-cols-[1fr_380px]">
      {/* Globe + status */}
      <div className="relative flex flex-col items-center justify-center overflow-hidden">
        <Globe regions={regions} selectedRegionId={selectedRegion} stage={stage} size={440} />
        <motion.div
          key={connect.stage}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-2 flex flex-col items-center text-center"
        >
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${stage === "connected" ? "bg-[var(--ok)]" : busy ? "bg-[var(--warn)]" : "bg-[var(--text-muted)]"}`} />
            <span className="text-lg font-semibold">
              {stage === "connected" ? "Secured" : busy ? "Connecting…" : "Not connected"}
            </span>
          </div>
          <p className="mt-1 h-5 text-sm text-[var(--text-secondary)]">{connect.detail ?? "Pick a region and connect"}</p>
        </motion.div>

        {stage === "connected" && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-4 flex items-center gap-8">
            <Odometer label="Download" value={down.value} unit={down.unit} />
            <Odometer label="Upload" value={up.value} unit={up.unit} />
          </motion.div>
        )}
      </div>

      {/* Right rail */}
      <div className="flex flex-col gap-4 overflow-y-auto border-l border-[var(--border-subtle)] p-5">
        {stage === "idle" ? (
          <>
            <RegionPicker regions={regions} selected={selectedRegion} onSelect={setSelectedRegion} />
            <VpnNodes />
            <InstancePicker types={types} selected={selectedType} onSelect={setSelectedType} />
            <Button onClick={doConnect} className="w-full py-3">
              <Power size={17} /> Connect
            </Button>
          </>
        ) : (
          <>
            <Card>
              <div className="mb-3 flex items-center justify-between">
                <span className="text-sm font-medium">Live throughput</span>
                <Badge tone="accent"><Zap size={11} /> {(metrics?.nicPct ?? 0).toFixed(0)}% NIC</Badge>
              </div>
              <ThroughputChart data={rxHistory.length ? rxHistory : [0, 0]} width={330} height={140} />
            </Card>

            <Card>
              <div className="mb-3 text-sm font-medium">Server vitals</div>
              <div className="flex flex-col gap-3">
                <Gauge2 icon={<Cpu size={14} />} label="CPU" pct={metrics?.cpuPct ?? 0} />
                <Gauge2 icon={<MemoryStick size={14} />} label="Memory" pct={metrics?.memPct ?? 0} />
                <Gauge2 icon={<Activity size={14} />} label="NIC" pct={metrics?.nicPct ?? 0} />
              </div>
            </Card>

            <div className="grid grid-cols-2 gap-3">
              <Card className="!p-4">
                <div className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]"><DollarSign size={12} /> Session cost</div>
                <div className="mono mt-1 text-xl font-semibold">${cost.accruedUsd.toFixed(4)}</div>
                <div className="mono text-[10px] text-[var(--text-muted)]">${cost.hourlyUsd}/hr</div>
              </Card>
              <Card className="!p-4">
                <div className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]"><Gauge size={12} /> Latency</div>
                <div className="mono mt-1 text-xl font-semibold">{(metrics?.latencyMs ?? 0).toFixed(0)}<span className="text-sm font-normal"> ms</span></div>
                <div className="mono text-[10px] text-[var(--text-muted)]">to exit node</div>
              </Card>
            </div>

            {metrics && (
              <div className="mono text-xs text-[var(--text-muted)]">
                Transferred {fmtBytes((rxHistory.reduce((a, b) => a + b, 0)) * 2)} this session
              </div>
            )}

            <Button variant="danger" onClick={doDisconnect} className="w-full py-3">
              <Power size={17} /> Disconnect &amp; destroy
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

function Odometer({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <div className="text-center">
      <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mono mt-0.5 text-3xl font-bold tabular-nums text-accent">
        {value}
        <span className="ml-1 text-sm font-normal text-[var(--text-secondary)]">{unit}</span>
      </div>
    </div>
  );
}

function RegionPicker({ regions, selected, onSelect }: { regions: Region[]; selected: string; onSelect: (id: string) => void }) {
  return (
    <div>
      <div className="mb-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">Region</div>
      <div className="flex max-h-[280px] flex-col gap-1 overflow-y-auto pr-1">
        {regions.map((r) => (
          <button
            key={r.id}
            onClick={() => onSelect(r.id)}
            className={`flex items-center justify-between rounded-[10px] border px-3 py-2 text-left text-sm transition-colors ${
              r.id === selected ? "border-[var(--accent)]/50 bg-[var(--accent)]/10" : "border-[var(--border-subtle)] hover:border-[var(--border-strong)]"
            }`}
          >
            <span className="flex items-center gap-2">
              <span className="mono text-[10px] text-[var(--text-muted)]">{r.country}</span>
              {r.label}
            </span>
            <span className="mono text-xs text-[var(--text-muted)]">{r.latencyMs}ms</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function InstancePicker({ types, selected, onSelect }: { types: InstanceType[]; selected: string; onSelect: (id: string) => void }) {
  return (
    <div>
      <div className="mb-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">Instance size</div>
      <div className="grid grid-cols-2 gap-1.5">
        {types.map((t) => (
          <button
            key={t.id}
            onClick={() => onSelect(t.id)}
            className={`rounded-[10px] border px-3 py-2 text-left transition-colors ${
              t.id === selected ? "border-[var(--accent)]/50 bg-[var(--accent)]/10" : "border-[var(--border-subtle)] hover:border-[var(--border-strong)]"
            }`}
          >
            <div className="text-xs font-medium">{t.label}</div>
            <div className="mono text-[10px] text-[var(--text-muted)]">${t.hourlyUsd}/hr</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function Gauge2({ icon, label, pct }: { icon: React.ReactNode; label: string; pct: number }) {
  const tone = pct > 85 ? "var(--warn)" : "var(--accent)";
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">{icon} {label}</span>
        <span className="mono text-[var(--text-muted)]">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[var(--bg-inset)]">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: tone }} />
      </div>
    </div>
  );
}

function VpnNodes() {
  const [enabled, setEnabled] = useState(false);
  const [nodes, setNodes] = useState<VpnNode[]>([]);
  const [cost, setCost] = useState<VpnCostSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = async () => {
    setBusy(true);
    setMsg("");
    try {
      const on = await vpnRealEnabled();
      setEnabled(on);
      if (on) {
        const [n, c] = await Promise.all([vpnNodes(), vpnCostSummary()]);
        setNodes(n);
        setCost(c);
      }
    } catch (e) {
      setMsg(`Couldn't load nodes: ${errMsg(e)}`);
    }
    setBusy(false);
  };

  useEffect(() => {
    void refresh();
  }, []);

  const act = async (id: string, action: "start" | "stop" | "reboot" | "delete") => {
    if (action === "delete" && !confirm("Destroy this node? This permanently deletes it (and stops its billing).")) return;
    setBusy(true);
    setMsg("");
    try {
      await vpnNodeAction(id, action);
      await refresh();
    } catch (e) {
      setMsg(`Action failed: ${errMsg(e)}`);
      setBusy(false);
    }
  };

  const destroyAll = async () => {
    if (!confirm("Destroy ALL exit nodes? This stops all billing and disconnects you.")) return;
    setBusy(true);
    setMsg("");
    try {
      const n = await vpnNodesDestroyAll();
      setMsg(`Destroyed ${n} node${n === 1 ? "" : "s"}.`);
      await refresh();
    } catch (e) {
      setMsg(`Couldn't destroy all: ${errMsg(e)}`);
      setBusy(false);
    }
  };

  if (!enabled) return null; // only meaningful in real-VPN (Linode) mode

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center justify-between text-sm font-medium">
        <span className="flex items-center gap-2">
          <Cloud size={15} /> VPN exit nodes
        </span>
        <button onClick={() => void refresh()} disabled={busy} className="text-xs text-[var(--accent)] hover:underline">
          {busy ? "…" : "Refresh"}
        </button>
      </div>

      {cost && cost.nodeCount > 0 && (
        <div className="mb-3 rounded-[10px] border border-[var(--border-strong)] p-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[var(--text-secondary)]">
              {cost.nodeCount} node{cost.nodeCount === 1 ? "" : "s"} · {cost.running} running · {cost.stopped} stopped
            </span>
            <span className="font-medium">~${cost.hourlyUsd.toFixed(4)}/hr</span>
          </div>
          <p className="mt-1 text-[var(--text-muted)]">
            A stopped node still bills — only <span className="font-medium">Destroy</span> stops the meter.
          </p>
        </div>
      )}

      {nodes.length === 0 ? (
        <p className="text-xs text-[var(--text-secondary)]">
          No exit nodes right now. Connecting on the VPN screen creates one; use “Disconnect &amp; keep” to power one
          off without destroying it.
        </p>
      ) : (
        <div className="space-y-2">
          {nodes.map((n) => (
            <div key={n.id} className="flex flex-wrap items-center gap-2 rounded-[10px] border border-[var(--border-subtle)] p-2 text-xs">
              <span className="mono">{n.region}</span>
              <Badge tone={n.state === "running" ? "ok" : n.state === "stopped" ? "neutral" : "accent"}>{n.state}</Badge>
              {n.current && <Badge tone="accent">connected</Badge>}
              {n.kept && <Badge tone="neutral">kept</Badge>}
              <span className="text-[var(--text-muted)]">~${n.hourlyUsd.toFixed(4)}/hr</span>
              <span className="ml-auto flex gap-2">
                {n.state === "stopped" ? (
                  <button onClick={() => void act(n.id, "start")} disabled={busy} className="text-[var(--accent)] hover:underline">Start</button>
                ) : (
                  <button onClick={() => void act(n.id, "stop")} disabled={busy} className="text-[var(--accent)] hover:underline">Stop</button>
                )}
                <button onClick={() => void act(n.id, "reboot")} disabled={busy} className="text-[var(--accent)] hover:underline">Reboot</button>
                <button onClick={() => void act(n.id, "delete")} disabled={busy} className="text-[var(--danger)] hover:underline">Destroy</button>
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="mt-3 flex items-center gap-3">
        {nodes.length > 0 && (
          <button onClick={() => void destroyAll()} disabled={busy} className={btnCls}>
            Destroy all nodes
          </button>
        )}
        {msg && <span className="text-xs text-[var(--text-muted)]">{msg}</span>}
      </div>
    </Card>
  );
}
