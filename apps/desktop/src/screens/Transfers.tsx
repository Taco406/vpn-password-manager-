// Transfers — "send to my devices": encrypted, zero-knowledge file transfer between the user's
// own devices (this desktop, the other desktop, the iPhone). The file is sealed locally into an
// opaque SFIL blob under the vault key and relayed through the sync server, which only ever stores
// ciphertext and a size. Any of the user's signed-in devices holding the same vault key opens it.

import { useCallback, useEffect, useRef, useState } from "react";
import { Send, Download, Trash2, RefreshCw, Upload, ArrowDownToLine } from "lucide-react";
import {
  transferList,
  transferSend,
  transferSendBundle,
  transferDownload,
  transferDelete,
  syncDevices,
  syncStatus,
  TRANSFER_MAX_BYTES,
  type TransferItem,
  type TransferRetention,
  type TransferDownloadResult,
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

/** The bare file-name component of a possibly-nested bundle path (browsers flatten on save anyway). */
function baseName(p: string): string {
  return p.split(/[/\\]/).pop() || p;
}

/** All files from a drop, recursing into any dropped folder (best-effort via webkitGetAsEntry) so a
 *  whole folder becomes one bundle; falls back to the flat FileList when the entry API is absent. */
async function filesFromDrop(dt: DataTransfer): Promise<File[]> {
  type Entry = {
    isFile: boolean;
    isDirectory: boolean;
    name: string;
    file?: (cb: (f: File) => void, err: (e: unknown) => void) => void;
    createReader?: () => { readEntries: (cb: (e: Entry[]) => void, err: (e: unknown) => void) => void };
  };
  const roots = dt.items
    ? Array.from(dt.items)
        .map((it) => (it as unknown as { webkitGetAsEntry?: () => Entry | null }).webkitGetAsEntry?.() ?? null)
        .filter((e): e is Entry => !!e)
    : [];
  if (roots.length === 0) return Array.from(dt.files);

  const out: File[] = [];
  const walk = async (entry: Entry, prefix: string): Promise<void> => {
    if (entry.isFile && entry.file) {
      const f = await new Promise<File>((res, rej) => entry.file!(res, rej));
      const rel = prefix ? `${prefix}/${f.name}` : f.name;
      out.push(new File([f], rel, { type: f.type, lastModified: f.lastModified }));
    } else if (entry.isDirectory && entry.createReader) {
      const reader = entry.createReader();
      const readBatch = () =>
        new Promise<Entry[]>((res, rej) => reader.readEntries(res, rej));
      const sub = prefix ? `${prefix}/${entry.name}` : entry.name;
      let batch = await readBatch();
      while (batch.length > 0) {
        for (const kid of batch) await walk(kid, sub);
        batch = await readBatch();
      }
    }
  };
  for (const r of roots) await walk(r, "");
  return out;
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
  const [dragOver, setDragOver] = useState(false);
  const [passphrase, setPassphrase] = useState(""); // optional send-side password
  const [unlock, setUnlock] = useState<{ id: string; pw: string } | null>(null); // receive-side prompt
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

  // Send one file as a normal transfer, or several (a multi-select or a dragged folder) as one
  // bundle. Files are already compressed by the seal, so bundling is the space win, not re-zipping.
  const onFiles = async (files: File[]) => {
    if (files.length === 0) return;
    const total = files.reduce((s, f) => s + f.size, 0);
    if (total > TRANSFER_MAX_BYTES) {
      setMsg(
        files.length === 1
          ? `"${files[0].name}" is ${fmtBytes(total)} — the limit is 25 MB per transfer.`
          : `Those ${files.length} files are ${fmtBytes(total)} together — the limit is 25 MB per transfer. Send fewer at once.`,
      );
      return;
    }
    setBusy(true);
    const to = recipient ? nameOf(recipient) : "all your devices";
    try {
      const pw = passphrase.trim() || undefined;
      const locked = pw ? " · password-protected" : "";
      if (files.length === 1) {
        setMsg(`Encrypting and sending "${files[0].name}"…`);
        const b64 = await fileToBase64(files[0]);
        const r = await transferSend(recipient || null, files[0].name, b64, retentionOf(retMode, ttlDays), pw);
        setMsg(`Sent "${r.filename}" (${fmtBytes(r.blobBytes)} encrypted${locked}) to ${to}.`);
      } else {
        setMsg(`Encrypting and sending ${files.length} files…`);
        const payload = await Promise.all(
          files.map(async (f) => ({ name: f.name, dataB64: await fileToBase64(f) })),
        );
        const r = await transferSendBundle(recipient || null, payload, retentionOf(retMode, ttlDays), pw);
        setMsg(`Sent ${files.length} files (${fmtBytes(r.blobBytes)} encrypted${locked}) to ${to}.`);
      }
      await refresh();
      setPassphrase("");
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (busy || !signedIn) return;
    const files = await filesFromDrop(e.dataTransfer);
    if (files.length) void onFiles(files);
  };

  // Save a downloaded transfer — several files for a bundle, one otherwise.
  const saveResult = (f: TransferDownloadResult) => {
    if (f.bundle && f.bundle.length > 0) {
      for (const bf of f.bundle) saveBase64(baseName(bf.name), "application/octet-stream", bf.dataB64);
      setMsg(`Saved ${f.bundle.length} files (${fmtBytes(f.sizeBytes)}). Check your Downloads folder.`);
    } else {
      saveBase64(f.filename, f.mime, f.dataB64);
      setMsg(`Saved "${f.filename}" (${fmtBytes(f.sizeBytes)}). Check your Downloads folder.`);
    }
  };

  const download = async (it: TransferItem) => {
    setBusy(true);
    setMsg("Downloading and decrypting…");
    try {
      const f = await transferDownload(it.id);
      if (f.needsPassphrase) {
        setUnlock({ id: it.id, pw: "" });
        setMsg("This file is password-protected — enter its password to open it.");
      } else {
        saveResult(f);
      }
    } catch (e) {
      setMsg(errMsg(e));
    }
    setBusy(false);
  };

  // Retry a password-protected download with the entered password.
  const submitUnlock = async () => {
    if (!unlock || !unlock.pw.trim()) return;
    setBusy(true);
    setMsg("Unlocking…");
    try {
      const f = await transferDownload(unlock.id, unlock.pw);
      if (f.needsPassphrase) {
        setMsg("That password didn't open the file — check it and try again.");
      } else {
        saveResult(f);
        setUnlock(null);
      }
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
      <Card className={`mb-4 transition-shadow ${dragOver ? "ring-2 ring-[var(--accent)]" : ""}`}>
       <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!busy && signedIn) setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => void onDrop(e)}
       >
        <div className="mb-2 flex items-center gap-2 text-sm font-medium">
          <Upload size={15} /> Send files to your devices
        </div>
        <p className="mb-3 text-xs text-[var(--text-secondary)]">
          Files are encrypted on this device with your vault key before they leave. The server stores
          only ciphertext and a size. Up to 25 MB per transfer — pick several (or drag a whole folder
          onto this card) and they go together as one bundle.
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
            multiple
            disabled={busy || !signedIn}
            onChange={(e) => {
              const fs = e.target.files ? Array.from(e.target.files) : [];
              if (fs.length) void onFiles(fs);
            }}
            className="text-xs text-[var(--text-secondary)] file:mr-3 file:rounded-[8px] file:border-0 file:bg-[var(--accent)]/15 file:px-3 file:py-1.5 file:text-[var(--accent)] hover:file:bg-[var(--accent)]/25"
          />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <label className="text-xs text-[var(--text-muted)]">
            Password{" "}
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="optional"
              disabled={busy || !signedIn}
              className="w-40 rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-2 py-1.5 text-xs text-[var(--text-primary)] disabled:opacity-50"
            />
          </label>
          {passphrase.trim() && (
            <span className="text-[11px] text-[var(--warn)]">
              A second lock only this password opens — it can’t be recovered, so share it separately
              and don’t forget it.
            </span>
          )}
        </div>
        <p className="mt-2 text-[11px] text-[var(--text-muted)]">
          {dragOver ? "Drop to send…" : retentionBlurb(retMode, ttlDays)}
        </p>
        {msg && <p className="mt-3 text-xs text-[var(--text-muted)]">{msg}</p>}
       </div>
      </Card>

      {unlock && (
        <Card className="mb-4 border border-[var(--accent)]/40">
          <div className="mb-2 text-sm font-medium">Password-protected file</div>
          <p className="mb-2 text-xs text-[var(--text-secondary)]">
            The sender locked this transfer with a password. Enter it to decrypt and save.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="password"
              autoFocus
              value={unlock.pw}
              onChange={(e) => setUnlock({ id: unlock.id, pw: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === "Enter") void submitUnlock();
              }}
              placeholder="Password"
              disabled={busy}
              className="w-52 rounded-[8px] border border-[var(--border-strong)] bg-[var(--bg-inset)] px-2 py-1.5 text-xs text-[var(--text-primary)] disabled:opacity-50"
            />
            <button
              onClick={() => void submitUnlock()}
              disabled={busy || !unlock.pw.trim()}
              className={`${btnCls} !py-1 disabled:opacity-50`}
            >
              Open
            </button>
            <button
              onClick={() => setUnlock(null)}
              disabled={busy}
              className="text-xs text-[var(--text-muted)] hover:underline disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </Card>
      )}

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
