// Global command palette (Cmd/Ctrl-K): search the vault and jump to actions.
import { Command } from "cmdk";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, KeyRound, Globe2, HeartPulse, Plus } from "lucide-react";
import type { ItemSummary } from "@sentinel/shared";
import { bridge } from "../../bridge";
import { Favicon } from "../ui";

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) void bridge.vaultList().then(setItems);
  }, [open]);

  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center bg-black/50 pt-[14vh] backdrop-blur-sm" onClick={() => setOpen(false)}>
      <div className="w-[560px] max-w-[92vw]" onClick={(e) => e.stopPropagation()}>
        <Command className="surface-overlay overflow-hidden shadow-2xl accent-glow" label="Command palette">
          <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] px-4">
            <Search size={16} className="text-[var(--text-muted)]" />
            <Command.Input
              autoFocus
              placeholder="Search vault or jump to…"
              className="w-full bg-transparent py-3.5 text-sm outline-none placeholder:text-[var(--text-muted)]"
            />
            <kbd className="mono rounded bg-[var(--bg-inset)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]">ESC</kbd>
          </div>
          <Command.List className="max-h-[52vh] overflow-y-auto p-2">
            <Command.Empty className="px-3 py-6 text-center text-sm text-[var(--text-muted)]">No results.</Command.Empty>
            <Command.Group heading="Actions" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-[var(--text-muted)]">
              <PaletteItem onSelect={() => go("/vault/new")} icon={<Plus size={16} />}>New login</PaletteItem>
              <PaletteItem onSelect={() => go("/vpn")} icon={<Globe2 size={16} />}>Connect VPN</PaletteItem>
              <PaletteItem onSelect={() => go("/health")} icon={<HeartPulse size={16} />}>Run health audit</PaletteItem>
            </Command.Group>
            <Command.Group heading="Vault" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-[var(--text-muted)]">
              {items.map((it) => (
                <PaletteItem key={it.id} value={`${it.title} ${it.username ?? ""}`} onSelect={() => go(`/vault/${it.id}`)} icon={<Favicon domain={it.faviconDomain} title={it.title} />}>
                  <div className="flex flex-col">
                    <span>{it.title}</span>
                    {it.username && <span className="text-xs text-[var(--text-muted)]">{it.username}</span>}
                  </div>
                </PaletteItem>
              ))}
            </Command.Group>
          </Command.List>
        </Command>
      </div>
    </div>
  );
}

function PaletteItem({
  children,
  onSelect,
  icon,
  value,
}: {
  children: React.ReactNode;
  onSelect: () => void;
  icon?: React.ReactNode;
  value?: string;
}) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-3 rounded-[8px] px-2 py-2 text-sm data-[selected=true]:bg-[var(--accent)]/12 data-[selected=true]:text-[var(--accent)]"
    >
      {icon}
      {children}
    </Command.Item>
  );
}
