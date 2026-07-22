import { useEffect } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { useApp } from "./stores/app";
import { checkForUpdate } from "./updater";
import { Layout } from "./components/Layout";
import { CommandPalette } from "./components/palette/CommandPalette";
import { Unlock } from "./screens/Unlock";
import { SetupWizard } from "./screens/SetupWizard";
import { Vault } from "./screens/Vault";
import { ItemEditor } from "./screens/ItemEditor";
import { Vpn } from "./screens/Vpn";
import { Health } from "./screens/Health";
import { Devices } from "./screens/Devices";
import { Servers } from "./screens/Servers";
import { Tools } from "./screens/Tools";
import { Experimental } from "./screens/Experimental";
import { Settings } from "./screens/Settings";
import { Report } from "./screens/Report";

export function App() {
  const init = useApp((s) => s.init);
  const refreshSettings = useApp((s) => s.refreshSettings);
  useEffect(() => {
    init();
    void refreshSettings();
    // Silently check for an app update on launch (no-op outside the Tauri shell).
    void checkForUpdate();
  }, [init, refreshSettings]);

  return (
    <HashRouter>
      <CommandPalette />
      <Routes>
        <Route path="/unlock" element={<Unlock />} />
        <Route path="/setup" element={<SetupWizard />} />
        <Route element={<Gate />}>
          <Route element={<Layout />}>
            <Route path="/vault" element={<Vault />} />
            <Route path="/vault/new" element={<ItemEditor />} />
            <Route path="/vault/:id/edit" element={<ItemEditor />} />
            <Route path="/vault/:id" element={<Vault />} />
            <Route path="/vpn" element={<Vpn />} />
            <Route path="/health" element={<Health />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/servers" element={<Servers />} />
            <Route path="/tools" element={<Tools />} />
            <Route path="/experimental" element={<Experimental />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/report/:ym" element={<Report />} />
            <Route path="/report" element={<Report />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/vault" replace />} />
      </Routes>
    </HashRouter>
  );
}

// Gate protected routes behind the lock screen — unless a screenshot/demo query asks
// to start unlocked. Params live in the top-level window query (before the hash).
function Gate() {
  const locked = useApp((s) => s.locked);
  const setLocked = useApp((s) => s.setLocked);
  const settings = useApp((a) => a.settings);
  const wantsUnlocked = new URLSearchParams(window.location.search).get("unlocked") === "1";

  useEffect(() => {
    if (wantsUnlocked) setLocked(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (locked && !wantsUnlocked) {
    return <Unlock />;
  }
  // First-run: once settings have loaded, send users who haven't finished (or skipped) the setup
  // wizard to it. Wait for `settings` to load (avoid a flash), and let the screenshot/demo
  // `?unlocked=1` escape hatch bypass onboarding entirely.
  if (settings && !settings.onboardingComplete && !wantsUnlocked) {
    return <Navigate to="/setup" replace />;
  }
  return <OutletProxy />;
}

// Small indirection so Gate can sit as a layout route.
import { Outlet } from "react-router-dom";
function OutletProxy() {
  return <Outlet />;
}
