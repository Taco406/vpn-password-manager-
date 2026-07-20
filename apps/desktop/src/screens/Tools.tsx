import { useState } from "react";
import { MapPin, Timer, Search, Loader2 } from "lucide-react";
import { netMyIp, netPing, netDns, type MyIp, type PingResult } from "../bridge";
import { Card, SectionTitle } from "../components/ui";
import { inputCls, btnCls, errMsg } from "../components/kit";

/** Networking tools: verify your public IP + apparent location, measure latency, resolve DNS. */
export function Tools() {
  return (
    <div className="mx-auto max-w-3xl px-8 py-8">
      <SectionTitle hint="network diagnostics">Tools</SectionTitle>
      <MyLocation />
      <Ping />
      <Dns />
    </div>
  );
}

function MyLocation() {
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<MyIp | null>(null);
  const [err, setErr] = useState("");

  const check = async () => {
    setBusy(true);
    setErr("");
    try {
      setData(await netMyIp());
    } catch (e) {
      setData(null);
      setErr(errMsg(e));
    }
    setBusy(false);
  };

  const place = data
    ? [data.city, data.region, data.country].filter(Boolean).join(", ")
    : "";

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <MapPin size={15} /> My IP &amp; location
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Shows the public IP and rough location the internet sees you at right now. With the VPN
        connected this should be your <span className="font-medium">exit server’s</span> location,
        not your real one — the quickest way to confirm the tunnel is working.
      </p>
      <button onClick={() => void check()} disabled={busy} className={btnCls}>
        {busy ? <span className="inline-flex items-center gap-1.5"><Loader2 size={14} className="animate-spin" /> Checking…</span> : "Check my location"}
      </button>

      {data && (
        <div className="mt-3 space-y-1 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3 text-sm">
          <div className="flex justify-between"><span className="text-[var(--text-muted)]">IP</span><span className="mono">{data.ip || "—"}</span></div>
          <div className="flex justify-between"><span className="text-[var(--text-muted)]">Location</span><span>{place || "—"}</span></div>
          <div className="flex justify-between"><span className="text-[var(--text-muted)]">Network</span><span className="max-w-[60%] truncate text-right">{data.org || "—"}</span></div>
        </div>
      )}
      {err && <p className="mt-2 text-xs text-[var(--danger)]">{err}</p>}
      <p className="mt-2 text-[11px] text-[var(--text-muted)]">
        This asks a public geo-IP service (ipapi.co) — the only way to learn your apparent public
        location. Nothing from your vault is sent.
      </p>
    </Card>
  );
}

function Ping() {
  const [host, setHost] = useState("1.1.1.1");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<PingResult | null>(null);
  const [err, setErr] = useState("");

  const run = async () => {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      setRes(await netPing(host));
    } catch (e) {
      setErr(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <Timer size={15} /> Ping (latency)
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Measures round-trip time to a host by timing a TCP connection (needs no admin rights).
      </p>
      <div className="flex items-center gap-2">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void run()}
          placeholder="example.com or 1.1.1.1"
          className={`${inputCls} flex-1`}
        />
        <button onClick={() => void run()} disabled={busy || !host.trim()} className={btnCls}>
          {busy ? "Pinging…" : "Ping"}
        </button>
      </div>
      {res && (
        <div className="mt-3 flex items-baseline gap-3 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
          <span className="text-2xl font-semibold text-[var(--accent)]">{res.ms.toFixed(0)}<span className="ml-1 text-sm text-[var(--text-muted)]">ms</span></span>
          <span className="text-xs text-[var(--text-muted)]">to <span className="mono">{res.ip}</span> :{res.port} · best of {res.attempts}</span>
        </div>
      )}
      {err && <p className="mt-2 text-xs text-[var(--danger)]">{err}</p>}
    </Card>
  );
}

function Dns() {
  const [host, setHost] = useState("example.com");
  const [busy, setBusy] = useState(false);
  const [ips, setIps] = useState<string[] | null>(null);
  const [err, setErr] = useState("");

  const run = async () => {
    setBusy(true);
    setErr("");
    setIps(null);
    try {
      setIps(await netDns(host));
    } catch (e) {
      setErr(errMsg(e));
    }
    setBusy(false);
  };

  return (
    <Card className="mb-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <Search size={15} /> DNS lookup
      </div>
      <p className="mb-3 text-xs text-[var(--text-secondary)]">
        Resolves a hostname to its IP addresses.
      </p>
      <div className="flex items-center gap-2">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void run()}
          placeholder="example.com"
          className={`${inputCls} flex-1`}
        />
        <button onClick={() => void run()} disabled={busy || !host.trim()} className={btnCls}>
          {busy ? "Resolving…" : "Resolve"}
        </button>
      </div>
      {ips && (
        <ul className="mt-3 space-y-1 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
          {ips.map((ip) => (
            <li key={ip} className="mono text-sm">{ip}</li>
          ))}
        </ul>
      )}
      {err && <p className="mt-2 text-xs text-[var(--danger)]">{err}</p>}
    </Card>
  );
}
