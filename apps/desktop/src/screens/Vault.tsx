import { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Search, Plus, Eye, EyeOff, Copy, Globe, StickyNote, CreditCard, User, Command as CmdIcon, ShieldCheck, Pencil } from "lucide-react";
import type { ItemDetail, ItemSummary } from "@sentinel/shared";
import { bridge } from "../bridge";
import { Favicon, Badge, Button } from "../components/ui";

const typeIcon = { login: Globe, note: StickyNote, card: CreditCard, identity: User } as const;

export function Vault() {
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const { id } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    void bridge.vaultList().then(setItems);
  }, []);

  const filtered = useMemo(
    () =>
      items.filter(
        (i) =>
          i.title.toLowerCase().includes(query.toLowerCase()) ||
          (i.username ?? "").toLowerCase().includes(query.toLowerCase()),
      ),
    [items, query],
  );

  const selectedId = id ?? filtered[0]?.id;

  return (
    <div className="flex h-full">
      <div className="flex w-[360px] shrink-0 flex-col border-r border-[var(--border-subtle)]">
        <div className="flex items-center gap-2 px-4 pb-3 pt-5">
          <div className="flex flex-1 items-center gap-2 rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3">
            <Search size={15} className="text-[var(--text-muted)]" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search"
              className="w-full bg-transparent py-2 text-sm outline-none placeholder:text-[var(--text-muted)]"
            />
            <kbd className="mono flex items-center gap-0.5 rounded bg-[var(--bg-raised)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]">
              <CmdIcon size={10} />K
            </kbd>
          </div>
          <Button onClick={() => navigate("/vault/new")} className="!px-2.5">
            <Plus size={16} />
          </Button>
        </div>
        <div className="mono px-4 pb-2 text-xs text-[var(--text-muted)]">{filtered.length} items</div>
        <div className="flex-1 overflow-y-auto px-2 pb-4">
          {filtered.map((it) => {
            const Icon = typeIcon[it.type];
            return (
              <button
                key={it.id}
                onClick={() => navigate(`/vault/${it.id}`)}
                className={`mb-1 flex w-full items-center gap-3 rounded-[10px] px-2 py-2 text-left transition-colors ${
                  it.id === selectedId ? "bg-[var(--accent)]/10" : "hover:bg-[var(--bg-overlay)]"
                }`}
              >
                <Favicon domain={it.faviconDomain} title={it.title} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{it.title}</div>
                  <div className="truncate text-xs text-[var(--text-muted)]">{it.username ?? it.type}</div>
                </div>
                <Icon size={14} className="text-[var(--text-muted)]" />
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {selectedId ? <ItemDetailPane id={selectedId} /> : <EmptyDetail />}
      </div>
    </div>
  );
}

function ItemDetailPane({ id }: { id: string }) {
  const [item, setItem] = useState<ItemDetail | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [password, setPassword] = useState<string>("");
  const [totp, setTotp] = useState<{ code: string; remainingMs: number } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    setRevealed(false);
    setPassword("");
    void bridge.vaultGet(id).then(setItem);
    void bridge.vaultRevealField(id, "password").then(setPassword);
  }, [id]);

  useEffect(() => {
    if (item?.hasTotp) void bridge.vaultTotp(id).then(setTotp);
  }, [id, item?.hasTotp]);

  if (!item) return <EmptyDetail />;
  const Icon = typeIcon[item.type];

  return (
    <div className="mx-auto max-w-2xl px-8 py-8">
      <div className="mb-6 flex items-center gap-4">
        <Favicon domain={item.faviconDomain} title={item.title} />
        <div className="flex-1">
          <h1 className="text-xl font-semibold">{item.title}</h1>
          <div className="mt-1 flex items-center gap-2 text-xs text-[var(--text-muted)]">
            <Icon size={13} /> {item.type}
            {item.tags.map((t) => (
              <Badge key={t}>{t}</Badge>
            ))}
          </div>
        </div>
        <Button variant="ghost" onClick={() => navigate(`/vault/${id}/edit`)} className="!px-3 !py-1.5">
          <Pencil size={14} /> Edit
        </Button>
      </div>

      <div className="surface divide-y divide-[var(--border-subtle)] p-0">
        {item.username && <Field label="Username" value={item.username} copyField="username" itemId={id} />}
        {item.type === "login" && (
          <div className="flex items-center gap-3 px-5 py-3.5">
            <div className="w-28 shrink-0 text-xs uppercase tracking-wide text-[var(--text-muted)]">Password</div>
            <div className="mono flex-1 truncate text-sm">{revealed ? password : "•".repeat(Math.min(16, password.length || 12))}</div>
            <button onClick={() => setRevealed((r) => !r)} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
              {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
            <button onClick={() => bridge.vaultCopyField(id, "password")} className="text-[var(--text-muted)] hover:text-[var(--accent)]">
              <Copy size={16} />
            </button>
          </div>
        )}
        {totp && (
          <div className="flex items-center gap-3 px-5 py-3.5">
            <div className="w-28 shrink-0 text-xs uppercase tracking-wide text-[var(--text-muted)]">One-time code</div>
            <div className="mono flex-1 text-lg tracking-widest text-accent">{totp.code.slice(0, 3)} {totp.code.slice(3)}</div>
            <div className="mono text-xs text-[var(--text-muted)]">{Math.ceil(totp.remainingMs / 1000)}s</div>
          </div>
        )}
        {item.urls.map((u) => (
          <Field key={u.url} label="Website" value={u.url} />
        ))}
        {item.notes && <Field label="Notes" value={item.notes} />}
      </div>

      <div className="mt-4 flex items-center gap-2 text-xs text-[var(--text-muted)]">
        <ShieldCheck size={13} className="text-[var(--ok)]" /> Encrypted per-item with XChaCha20-Poly1305 · updated {new Date(item.updatedAt).toLocaleDateString()}
      </div>
    </div>
  );
}

function Field({ label, value, copyField, itemId }: { label: string; value: string; copyField?: string; itemId?: string }) {
  return (
    <div className="flex items-center gap-3 px-5 py-3.5">
      <div className="w-28 shrink-0 text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mono flex-1 truncate text-sm">{value}</div>
      {copyField && itemId && (
        <button onClick={() => bridge.vaultCopyField(itemId, copyField)} className="text-[var(--text-muted)] hover:text-[var(--accent)]">
          <Copy size={16} />
        </button>
      )}
    </div>
  );
}

function EmptyDetail() {
  return (
    <div className="flex h-full flex-col items-center justify-center text-[var(--text-muted)]">
      <Globe size={40} className="mb-3 opacity-40" />
      <p className="text-sm">Select an item to view its details</p>
    </div>
  );
}

