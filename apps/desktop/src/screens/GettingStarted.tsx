// The "Getting started" setup checklist — one place that shows what a new user has set up vs. not,
// each with a one-click action. It reads the status getters that already exist across the app
// (nothing new on the backend) and reuses the Card/Badge/Button kit + the Devices SharedSettings
// pattern. The sidebar shows live progress and hides this once the essentials are done.

import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CheckCircle2, Circle, ChevronRight, Rocket, Sparkles } from "lucide-react";
import {
  getBridge,
  lockStatus,
  helloStatus,
  syncStatus,
  syncServerStatus,
  syncDevices,
  autofillStatus,
  vpnRealEnabled,
  serversConfig,
} from "../bridge";
import { Card, SectionTitle, Badge } from "../components/ui";

/** The setup signals, gathered once. All optional — the app works out of the box. */
interface Status {
  protectedVault: boolean; // master password OR fast unlock
  firstLogin: boolean;
  synced: boolean;
  multiDevice: boolean;
  autofill: boolean;
  realVpn: boolean;
  servers: boolean;
}

interface ChecklistItem {
  key: string;
  title: string;
  detail: string;
  done: boolean;
  cta: string;
  onAction: () => void;
}

/** Feeds the sidebar badge: essentials done / total, and whether everything essential is complete. */
export async function getSetupProgress(): Promise<{ done: number; total: number; complete: boolean }> {
  try {
    const [lock, hello, list] = await Promise.all([lockStatus(), helloStatus(), getBridge().vaultList()]);
    const essentials = [lock.passwordProtected || hello.enabled, (list?.length ?? 0) > 0];
    const done = essentials.filter(Boolean).length;
    return { done, total: essentials.length, complete: done === essentials.length };
  } catch {
    return { done: 0, total: 2, complete: false };
  }
}

export function GettingStarted() {
  const navigate = useNavigate();
  const [st, setSt] = useState<Status | null>(null);

  const refresh = useCallback(async () => {
    const [lock, hello, sync, server, devices, autofill, vpn, servers] = await Promise.all([
      lockStatus().catch(() => ({ passwordProtected: false }) as Awaited<ReturnType<typeof lockStatus>>),
      helloStatus().catch(() => ({ available: false, enabled: false })),
      syncStatus().catch(() => ({ signedIn: false }) as Awaited<ReturnType<typeof syncStatus>>),
      syncServerStatus().catch(() => ({ deployed: false, hourlyUsd: 0, monthlyUsd: 0 })),
      syncDevices().catch(() => []),
      autofillStatus().catch(() => ({ installed: false })),
      vpnRealEnabled().catch(() => false),
      serversConfig().catch(() => ({ linodeEnabled: false, hetznerEnabled: false })),
    ]);
    const list = await getBridge().vaultList().catch(() => []);
    setSt({
      protectedVault: lock.passwordProtected || hello.enabled,
      firstLogin: (list?.length ?? 0) > 0,
      synced: sync.signedIn || server.deployed,
      multiDevice: (devices?.length ?? 0) > 1,
      autofill: autofill.installed,
      realVpn: vpn,
      servers: servers.linodeEnabled || servers.hetznerEnabled,
    });
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const s = st;
  const essentials: ChecklistItem[] = [
    {
      key: "protect",
      title: "Protect your vault",
      detail: "Set a master password (and Face ID / Windows Hello) so only you can open NorthKey.",
      done: !!s?.protectedVault,
      cta: "Set it up",
      onAction: () => navigate("/settings"),
    },
    {
      key: "firstLogin",
      title: "Add your first login",
      detail: "Save a password — or import from Chrome, Bitwarden, or 1Password.",
      done: !!s?.firstLogin,
      cta: "Add a login",
      onAction: () => navigate("/vault/new"),
    },
  ];
  const powerups: ChecklistItem[] = [
    {
      key: "sync",
      title: "Sync across your devices",
      detail: "Deploy your own private sync server (one click) or sign in to an existing one.",
      done: !!s?.synced,
      cta: "Set up sync",
      onAction: () => navigate("/devices"),
    },
    {
      key: "multiDevice",
      title: "Add another device",
      detail: "Put your vault on a second computer or your iPhone with a QR code.",
      done: !!s?.multiDevice,
      cta: "Add a device",
      onAction: () => navigate("/devices"),
    },
    {
      key: "autofill",
      title: "Turn on browser autofill",
      detail: "Install the NorthKey extension so logins fill themselves in Chrome and Edge.",
      done: !!s?.autofill,
      cta: "Enable autofill",
      onAction: () => navigate("/experimental"),
    },
    {
      key: "vpn",
      title: "Connect the VPN",
      detail: "Spin up a throwaway private VPN exit in any region with your Linode token.",
      done: !!s?.realVpn,
      cta: "Set up VPN",
      onAction: () => navigate("/vpn"),
    },
    {
      key: "servers",
      title: "Watch your servers",
      detail: "Add your Linode or Hetzner token to see every server with live monitoring.",
      done: !!s?.servers,
      cta: "Add a token",
      onAction: () => navigate("/settings"),
    },
  ];

  const essDone = essentials.filter((i) => i.done).length;
  const allEssential = essDone === essentials.length;

  return (
    <div className="mx-auto max-w-2xl px-8 py-8">
      <SectionTitle hint="You can do these in any order">Getting started</SectionTitle>

      <Card className="mb-4 !p-4" glow={allEssential}>
        <div className="flex items-center gap-3">
          {allEssential ? (
            <Sparkles size={20} className="text-[var(--accent)]" />
          ) : (
            <Rocket size={20} className="text-[var(--accent)]" />
          )}
          <div className="flex-1">
            <div className="text-sm font-medium">
              {allEssential ? "You're set up — nice." : `Essentials · ${essDone} of ${essentials.length} done`}
            </div>
            <div className="text-xs text-[var(--text-secondary)]">
              {allEssential
                ? "Everything below is optional — add power-ups whenever you like."
                : "NorthKey already works. These two make it yours."}
            </div>
          </div>
          {allEssential && <Badge tone="ok">ready</Badge>}
        </div>
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
          <div
            className="h-full rounded-full bg-[var(--accent)] transition-all"
            style={{ width: `${(essDone / essentials.length) * 100}%` }}
          />
        </div>
      </Card>

      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">Essentials</div>
      <div className="mb-5 space-y-2">
        {essentials.map((item) => (
          <Row key={item.key} item={item} loading={!s} />
        ))}
      </div>

      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">Power-ups</div>
      <div className="space-y-2">
        {powerups.map((item) => (
          <Row key={item.key} item={item} loading={!s} />
        ))}
      </div>
    </div>
  );
}

function Row({ item, loading }: { item: ChecklistItem; loading: boolean }) {
  return (
    <div
      className={`flex items-center gap-3 rounded-[12px] border px-4 py-3 ${
        item.done
          ? "border-[var(--ok)]/25 bg-[var(--ok)]/[0.04]"
          : "border-[var(--border-subtle)] bg-[var(--bg-inset)]"
      }`}
    >
      {item.done ? (
        <CheckCircle2 size={18} className="shrink-0 text-[var(--ok)]" />
      ) : (
        <Circle size={18} className="shrink-0 text-[var(--text-muted)]" />
      )}
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{item.title}</div>
        <div className="text-xs text-[var(--text-secondary)]">{item.detail}</div>
      </div>
      {item.done ? (
        <Badge tone="ok">done</Badge>
      ) : (
        <button
          onClick={item.onAction}
          disabled={loading}
          className="inline-flex shrink-0 items-center gap-1 rounded-[10px] bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-[#04121a] hover:bg-[var(--accent-hover)] disabled:opacity-50"
        >
          {item.cta} <ChevronRight size={13} />
        </button>
      )}
    </div>
  );
}
