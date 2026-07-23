import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { Mountain, KeyRound, Globe2, HeartPulse, Smartphone, Settings as Cog, Lock, FlaskConical, Radar, Server, Send, Rocket } from "lucide-react";
import { useApp } from "../stores/app";
import { bridge } from "../bridge";
import { getSetupProgress } from "../screens/GettingStarted";
import { ClipboardCountdown } from "./ClipboardCountdown";

const nav = [
  { to: "/vault", label: "Vault", icon: KeyRound },
  { to: "/vpn", label: "VPN", icon: Globe2 },
  { to: "/health", label: "Health", icon: HeartPulse },
  { to: "/devices", label: "Devices", icon: Smartphone },
  { to: "/servers", label: "Servers", icon: Server },
  { to: "/transfers", label: "Transfers", icon: Send },
  { to: "/tools", label: "Tools", icon: Radar },
  { to: "/experimental", label: "Experimental", icon: FlaskConical },
  { to: "/settings", label: "Settings", icon: Cog },
];

export function Layout() {
  const connect = useApp((s) => s.connect);
  const connected = connect.stage === "connected";
  // Live setup progress feeds the "Get started" nav item, which hides once the essentials are done.
  const [setup, setSetup] = useState<{ done: number; total: number; complete: boolean } | null>(null);
  useEffect(() => {
    void getSetupProgress().then(setSetup);
    const t = window.setInterval(() => void getSetupProgress().then(setSetup), 15_000);
    return () => window.clearInterval(t);
  }, []);
  const showGetStarted = setup !== null && !setup.complete;

  return (
    <div className="flex h-full">
      <aside className="flex w-[220px] shrink-0 flex-col border-r border-[var(--border-subtle)] bg-[var(--bg-raised)] px-3 py-5">
        <div className="mb-7 px-2">
          <div className="flex items-center gap-2">
            <Mountain className="text-accent" size={22} />
            <span className="text-lg font-bold tracking-tight">
              NORTH<span className="text-accent">KEY</span>
            </span>
          </div>
          <div className="mt-0.5 text-[10px] leading-tight text-[var(--text-muted)]">
            Your network. Your passwords. <span className="text-accent">Your control.</span>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          {showGetStarted && (
            <NavLink
              to="/getting-started"
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-[10px] px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-[var(--accent)]/12 text-[var(--accent)]"
                    : "text-[var(--text-secondary)] hover:bg-[var(--bg-overlay)] hover:text-[var(--text-primary)]"
                }`
              }
            >
              <Rocket size={18} />
              <span className="flex-1">Get started</span>
              {setup && (
                <span className="rounded-full bg-[var(--accent)]/15 px-1.5 text-[10px] font-medium text-[var(--accent)]">
                  {setup.done}/{setup.total}
                </span>
              )}
            </NavLink>
          )}
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-[10px] px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-[var(--accent)]/12 text-[var(--accent)]"
                    : "text-[var(--text-secondary)] hover:bg-[var(--bg-overlay)] hover:text-[var(--text-primary)]"
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-3">
          <div className="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2.5">
            <div className="flex items-center gap-2 text-xs">
              <span className={`h-2 w-2 rounded-full ${connected ? "bg-[var(--ok)]" : "bg-[var(--text-muted)]"}`} />
              <span className="text-[var(--text-secondary)]">{connected ? "VPN connected" : "VPN off"}</span>
            </div>
            {connected && connect.egressIp && (
              <div className="mono mt-1 text-xs text-[var(--text-muted)]">{connect.egressIp}</div>
            )}
          </div>
          <button
            onClick={() => bridge.lock()}
            className="flex items-center gap-2 rounded-[10px] px-3 py-2 text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-overlay)] hover:text-[var(--text-primary)]"
          >
            <Lock size={16} /> Lock vault
          </button>
        </div>
      </aside>

      <main className="relative flex-1 overflow-y-auto">
        <Outlet />
        <ClipboardCountdown />
      </main>
    </div>
  );
}
