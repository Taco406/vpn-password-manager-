// Transfers — "send to my devices": encrypted, zero-knowledge file transfer between the user's
// own devices (this desktop, the other desktop, the iPhone). The file is sealed locally into an
// opaque SFIL blob under the vault key and relayed through the sync server, which only ever stores
// ciphertext and a size. Any of the user's signed-in devices holding the same vault key opens it.

import { useCallback, useEffect, useRef, useState } from "react";
import { Send, Download, Trash2, RefreshCw, Upload, ArrowDownToLine } from "lucide-react";
import {
  transferList,
  transferSend,
  transferDownload,
  transferDelete,
  syncDevices,
  syncStatus,
  TRANSFER_MAX_BYTES,
  type TransferItem,
  type TransferRetention,
  type SyncDevice,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";
import { btnCls, errMsg } from "../components/kit";
import { fmtBytes } from "../components/charts/ThroughputChart";

/** Read a picked File as base64 (no data: prefix), via the browser's own decoder. */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const s = String(r.result);
      const i = s.indexOf(",");
      resolve(i >= 0 ? s.slice(i + 1) : s);
    };
    r.onerror = () => reject(r.error ?? new Error("could not read file"));
    r.readAsDataURL(file);
  });
}

/** Save decrypted bytes (base64) to disk via a browser download — the OS save dialog picks where. */
function saveBase64(filename: string, mime: string, b64: string) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], { type: mime || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function timeAgo(unix: number): string {
  if (!unix) return "";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function expiresIn(unix: number): string {
  if (!unix) return "";
  const secs = unix - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "expired";
  const days = Math.floor(secs / 86400);
  if (days >= 1) return `expires in ${days}d`;
  const hrs = Math.floor(secs / 3600);
  if (hrs >= 1) return `expires in ${hrs}h`;
  return `expires in ${Math.max(1, Math.floor(secs / 60))} min`;
}

/** How the file is kept on the relay after sending. Maps to a {@link TransferRetention}. */
type RetentionMode = "days" | "onDownload" | "permanent";

function retentionOf(mode: RetentionMode, ttlDays: number): TransferRetention {
  if (mode === "permanent") return { permanent: true };
  if (mode === "onDownload") return { deleteOnDownload: true };
  return { ttlDays };
}

/** One-line human summary of the chosen retention, for the Send card. */
function retentionBlurb(mode: RetentionMode, ttlDays: number): string {
  if (mode === "permanent")
    return "Kept on your server until you delete it — counts against your storage quota.";
  if (mode === "onDownload")
    return "Deleted the moment one of your devices downloads it.";
  const d = Math.max(1, ttlDays);
  return `Deleted automatically after ${d} day${d === 1 ? "" : "s"}, downloaded or not.`;
}

export function Transfers() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [items, setItems] = useState<TransferItem[]>([]);
  const [devices, setDevices] = useState<SyncDevice[]>([]);
  const [recipient, setRecipient] = useState<string>(""); // "" = all my devices
  const [retMode, setRetMode] = useState<RetentionMode>("days");
  const [ttlDays, setTtlDays] = useState(1);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [loaded, setLoaded] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      const [list, devs] = await Promise.all([transferList(), syncDevices()]);
      setItems(list);
      setDevices(devs);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setLoaded(true);
  }, []);

  useEffect(() => {
    void syncStatus()
      .then((s) => setSignedIn(s.signedIn))
      .catch(() => setSignedIn(false));
  }, []);

  useEffect(() => {
    void refresh();
    const t = window.setInterval(() => void refresh(), 30_000);
    return () => window.clearInterval(t);
  }, [refresh]);

  // Map a device id to a friendly name (falls back to a short id when unknown, e.g. the phone
  // hasn't been listed yet).
  const nameOf = (id: string | null): string => {
    if (!id) return "All my devices";
    const d = devices.find((x) => x.id === id);
    return d ? d.name + (d.current ? " (this device)" : "") : id.slice(0, 8);
  };

  const onPick = async (file: File) => {
    if (file.size > TRANSFER_MAX_BYTES) {
      setMsg(`"${file.name}" is ${fmtBytes(file.size)} — the limit is 25 MB per transfer.`);
      return;
    }
    setBusy(true);
    setMsg(`Encrypting and sending "${file.name}"…`);
    try {
      const b64 = await fileToBase64(file);
      const r = await transferSend(recipient || null, file.name, b64, retentionOf(retMode, ttlDays));
      setMsg(
        `Sent "${r.filename}" (${fmtBytes(r.blobBytes)} encrypted) to ${
          recipient ? nameOf(recipient) : "all your devices"
        }.`,
      );
      await refresh();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const download = async (it: TransferItem) => {
    setBusy(true);
    setMsg("Downloading and decrypting…");
    try {
      const f = await transferDownload(it.id);
      saveBase64(f.filename, f.mime, f.dataB64);
      setMsg(`Saved "${f.filename}" (${fmtBytes(f.sizeBytes)}). Check your Downloads folder.`);
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const remove = async (it: TransferItem) => {
    setBusy(true);
    try {
      await transferDelete(it.id);
      await refresh();
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  const incoming = items.filter((i) => !i.outgoing);
  const outgoing = items.filter((i) => i.outgoing);

  return (
    <div className="mx-auto max-w-4xl px-8 py-8">
      <SectionTitle hint="End-to-end encrypted · your devices only">Transfers</SectionTitle>

      {signedIn === false && (
        <Card className="mb-4 border border-[var(--warn)]/40">
          <p className="text-xs text-[var(--warn)]">
            Sign in under <span className="font-medium">Devices</span> to send files between your
            devices. Transfers relay through your own sync server, encrypted end-to-end.
          </p>
        </Card>
      )}

      {/* Send */}
      <Card className="mb-4">
        <div className="mb-2 flex items-center gap-2 text-sm font-medium">
          <Upload size={15} /> Send a file to your devices
        </div>
        <p className="mb-3 text-xs text-[var(--text-secondary)]">
          The file is encrypted on this device with your vault key before it leaves. The server
          stores only ciphertext and a size. Up to 25 MB per file.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-[var(--text-muted)]">
            To{" "}
            <select
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              disabled={busy || !signedIn}
              className="rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-2 py-1.5 text-xs text-[var(--text-primary)] disabled:opacity-50"
            >
              <option value="">All my devices</option>
              {devices
                .filter((d) => !d.current)
                .map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name} · {d.platform}
                  </option>
                ))}
            </select>
          </label>
          <label className="text-xs text-[var(--text-muted)]">
            Keep{" "}
            <select
              value={retMode}
              onChange={(e) => setRetMode(e.target.value as RetentionMode)}
              disabled={busy || !signedIn}
              className="rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-2 py-1.5 text-xs text-[var(--text-primary)] disabled:opacity-50"
            >
              <option value="days">for a few days</option>
              <option value="onDownload">until downloaded</option>
              <option value="permanent">permanently</option>
            </select>
          </label>
          {retMode === "days" && (
            <label className="flex items-center gap-1 text-xs text-[var(--text-muted)]">
              <input
                type="number"
                min={1}
                max={365}
                value={ttlDays}
                onChange={(e) => setTtlDays(Math.max(1, Math.min(365, Number(e.target.value) || 1)))}
                disabled={busy || !signedIn}
                className="w-16 rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-2 py-1.5 text-xs text-[var(--text-primary)] disabled:opacity-50"
              />
              day{ttlDays === 1 ? "" : "s"}
            </label>
          )}
          <input
            ref={fileRef}
            type="file"
            disabled={busy || !signedIn}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void onPick(f);
            }}
            className="text-xs text-[var(--text-secondary)] file:mr-3 file:rounded-[8px] file:border-0 file:bg-[var(--accent)]/15 file:px-3 file:py-1.5 file:text-[var(--accent)] hover:file:bg-[var(--accent)]/25"
          />
        </div>
        <p className="mt-2 text-[11px] text-[var(--text-muted)]">{retentionBlurb(retMode, ttlDays)}</p>
        {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
      </Card>

      {/* Inbox */}
      <Card className="mb-4">
        <div className="mb-2 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-medium">
            <ArrowDownToLine size={15} /> Incoming
          </div>
          <button
            onClick={() => void refresh()}
            className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
        {incoming.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">
            {loaded ? "Nothing waiting for this device." : "Loading…"}
          </p>
        ) : (
          <div className="space-y-1.5">
            {incoming.map((it) => (
              <Row
                key={it.id}
                title={`from ${nameOf(it.senderDeviceId)}`}
                it={it}
                busy={busy}
                onPrimary={() => void download(it)}
                primaryLabel="Save"
                primaryIcon={<Download size={13} />}
                onDelete={() => void remove(it)}
              />
            ))}
          </div>
        )}
      </Card>

      {/* Outbox */}
      <Card>
        <div className="mb-2 flex items-center gap-2 text-sm font-medium">
          <Send size={15} /> Sent
        </div>
        {outgoing.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">
            {loaded ? "You haven't sent anything yet." : "Loading…"}
          </p>
        ) : (
          <div className="space-y-1.5">
            {outgoing.map((it) => (
              <Row
                key={it.id}
                title={`to ${nameOf(it.recipientDeviceId)}`}
                it={it}
                busy={busy}
                onDelete={() => void remove(it)}
              />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function Row({
  title,
  it,
  busy,
  onPrimary,
  primaryLabel,
  primaryIcon,
  onDelete,
}: {
  title: string;
  it: TransferItem;
  busy: boolean;
  onPrimary?: () => void;
  primaryLabel?: string;
  primaryIcon?: React.ReactNode;
  onDelete: () => void;
}) {
  const expired = it.state === "expired";
  return (
    <div className="flex items-center justify-between rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2">
      <div className="min-w-0">
        <div className="truncate text-xs text-[var(--text-primary)]">
          {title} · <span className="mono">{fmtBytes(it.sizeBytes)}</span>
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10px] text-[var(--text-muted)]">
          <span>{timeAgo(it.createdAt)}</span>
          {it.state === "delivered" && <Badge tone="ok">delivered</Badge>}
          {it.permanent ? (
            <Badge tone="accent">kept</Badge>
          ) : it.deleteOnDownload ? (
            <span>· deletes on download</span>
          ) : (
            it.state === "pending" && <span>· {expiresIn(it.expiresAt)}</span>
          )}
          {expired && <Badge tone="warn">expired</Badge>}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {onPrimary && !expired && (
          <button
            onClick={onPrimary}
            disabled={busy}
            className={`${btnCls} inline-flex items-center gap-1 !py-1 disabled:opacity-50`}
          >
            {primaryIcon}
            {primaryLabel}
          </button>
        )}
        <button
          onClick={onDelete}
          disabled={busy}
          className="rounded-[8px] p-1.5 text-[var(--text-muted)] hover:text-[var(--danger)] disabled:opacity-50"
          aria-label="Delete transfer"
          title="Delete"
        >
          <Trash2 size={13} />
        </button>
      </div>
    </div>
  );
}
