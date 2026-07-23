//! The Servers screen backend: one unified view over every server the user owns —
//! all Linode instances (including NorthKey's own tagged nodes, labeled by role) and
//! all Hetzner Cloud servers — with power actions and real utilization metrics.
//!
//! Deliberately separate from `vpn.rs`'s tag-scoped node management: nothing here is
//! ever fed to the ephemeral orphan sweep, and powering the node that carries the
//! active VPN tunnel is refused (that teardown path lives on the VPN screen).

use sentinel_core::cloud::{
    netdata, watchdog, HetznerClient, LinodeClient, NetdataEndpoint, PowerAction, ServerEvent,
    ServerInfo, ServerManager, Snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::state::AppState;

const KC_SERVICE: &str = "com.sentinel.desktop";
const KC_HETZNER: &str = "hetzner-token";

fn hetzner_get_token() -> Option<String> {
    let entry = keyring::Entry::new(KC_SERVICE, KC_HETZNER).ok()?;
    entry
        .get_password()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn hetzner_set_token(token: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KC_SERVICE, KC_HETZNER).map_err(|e| e.to_string())?;
    if token.trim().is_empty() {
        let _ = entry.delete_credential();
        Ok(())
    } else {
        entry.set_password(token.trim()).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// command output shapes
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServersConfigOut {
    linode_enabled: bool,
    hetzner_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOut {
    provider: String,
    id: String,
    label: String,
    region: String,
    instance_type: String,
    state: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
    /// NorthKey roles derived from tags: "vpn" | "sync" | "vpn-always-on" | "external".
    roles: Vec<String>,
    created_at: Option<i64>,
    vcpus: u32,
    memory_mb: u32,
    disk_gb: u32,
    hourly: f64,
    monthly: f64,
    currency: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderError {
    provider: String,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServersListOut {
    servers: Vec<ServerOut>,
    errors: Vec<ProviderError>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsOut {
    /// `[unix_seconds, value]` pairs. CPU %, network bytes/s, disk IO ops/s.
    cpu_pct: Vec<[f64; 2]>,
    net_in_bps: Vec<[f64; 2]>,
    net_out_bps: Vec<[f64; 2]>,
    disk_io: Vec<[f64; 2]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotOut {
    id: String,
    label: String,
    created_at: Option<i64>,
    size_gb: Option<f64>,
    status: String,
}

fn snapshot_out(s: Snapshot) -> SnapshotOut {
    SnapshotOut {
        id: s.id,
        label: s.label,
        created_at: s.created_at,
        size_gb: s.size_gb,
        status: s.status,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerEventOut {
    action: String,
    status: String,
    created_at: Option<i64>,
    progress: Option<f64>,
}

fn event_out(e: ServerEvent) -> ServerEventOut {
    ServerEventOut {
        action: e.action,
        status: e.status,
        created_at: e.created_at,
        progress: e.progress,
    }
}

fn state_label(s: sentinel_core::cloud::InstanceState) -> &'static str {
    use sentinel_core::cloud::InstanceState as S;
    match s {
        S::Provisioning => "provisioning",
        S::Booting => "booting",
        S::Running => "running",
        S::Stopped => "stopped",
        S::Deleting => "deleting",
        S::Gone => "gone",
    }
}

fn roles_for(info: &ServerInfo) -> Vec<String> {
    let mut roles = Vec::new();
    for tag in &info.tags {
        match tag.as_str() {
            sentinel_core::cloud::EPHEMERAL_TAG => roles.push("vpn".to_string()),
            sentinel_core::cloud::SYNC_TAG => roles.push("sync".to_string()),
            sentinel_core::cloud::PERSISTENT_VPN_TAG => roles.push("vpn-always-on".to_string()),
            _ => {}
        }
    }
    if roles.is_empty() {
        roles.push("external".to_string());
    }
    roles
}

fn server_out(info: ServerInfo) -> ServerOut {
    let roles = roles_for(&info);
    ServerOut {
        provider: info.provider.as_str().to_string(),
        id: info.id,
        label: info.label,
        region: info.region,
        instance_type: info.instance_type,
        state: state_label(info.state).to_string(),
        ipv4: info.ipv4,
        ipv6: info.ipv6,
        roles,
        created_at: info.created_at,
        vcpus: info.vcpus,
        memory_mb: info.memory_mb,
        disk_gb: info.disk_gb,
        hourly: info.hourly,
        monthly: info.monthly,
        currency: info.currency.to_string(),
    }
}

fn points_out(points: &[sentinel_core::cloud::MetricPoint]) -> Vec<[f64; 2]> {
    points.iter().map(|p| [p.ts as f64, p.value]).collect()
}

/// Build the manager for one provider from its keychain token.
fn manager_for(provider: &str) -> Result<Box<dyn ServerManager>, String> {
    match provider {
        "linode" => {
            let token = crate::vpn::get_token()
                .ok_or("no Linode token — set one under Settings → VPN → Real VPN")?;
            Ok(Box::new(LinodeClient::new(token)))
        }
        "hetzner" => {
            let token = hetzner_get_token()
                .ok_or("no Hetzner token — set one under Settings → VPN → Hetzner Cloud")?;
            Ok(Box::new(HetznerClient::new(token)))
        }
        p => Err(format!("unknown provider: {p}")),
    }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

/// Which providers have tokens configured (drives the screen's empty states).
#[tauri::command]
pub fn servers_config() -> ServersConfigOut {
    ServersConfigOut {
        linode_enabled: crate::vpn::get_token().is_some(),
        hetzner_enabled: hetzner_get_token().is_some(),
    }
}

/// Save (or clear, with an empty string) the Hetzner Cloud API token.
#[tauri::command]
pub fn servers_set_hetzner_token(token: String) -> Result<(), String> {
    hetzner_set_token(&token)
}

/// Every server across every configured provider. Providers are fetched concurrently and
/// fail independently — one dead token still shows the other provider's fleet.
#[tauri::command]
pub async fn servers_list() -> Result<ServersListOut, String> {
    let linode = crate::vpn::get_token().map(LinodeClient::new);
    let hetzner = hetzner_get_token().map(HetznerClient::new);
    if linode.is_none() && hetzner.is_none() {
        return Err(
            "No provider tokens configured. Add your Linode and/or Hetzner Cloud API token \
             in Settings."
                .into(),
        );
    }

    let linode_fut = async {
        match &linode {
            Some(c) => Some(ServerManager::list_all(c).await),
            None => None,
        }
    };
    let hetzner_fut = async {
        match &hetzner {
            Some(c) => Some(c.list_all().await),
            None => None,
        }
    };
    let (linode_res, hetzner_res) = tokio::join!(linode_fut, hetzner_fut);

    let mut servers = Vec::new();
    let mut errors = Vec::new();
    for (name, res) in [("linode", linode_res), ("hetzner", hetzner_res)] {
        match res {
            Some(Ok(list)) => servers.extend(list.into_iter().map(server_out)),
            Some(Err(e)) => errors.push(ProviderError {
                provider: name.to_string(),
                message: e.to_string(),
            }),
            None => {}
        }
    }
    // Stable order: provider, then label.
    servers.sort_by(|a, b| {
        (a.provider.as_str(), a.label.as_str()).cmp(&(b.provider.as_str(), b.label.as_str()))
    });
    Ok(ServersListOut { servers, errors })
}

/// Utilization time series for one server (~`window_secs` back; Linode always returns ~24h
/// and is trimmed client-side).
#[tauri::command]
pub async fn servers_metrics(
    provider: String,
    id: String,
    window_secs: u32,
) -> Result<MetricsOut, String> {
    let mgr = manager_for(&provider)?;
    let m = mgr
        .metrics(&id, window_secs)
        .await
        .map_err(|e| e.to_string())?;
    // Trim to the requested window (Linode over-returns).
    let cutoff = m
        .cpu_pct
        .last()
        .map(|p| p.ts - window_secs as i64)
        .unwrap_or(0);
    let trim = |pts: &[sentinel_core::cloud::MetricPoint]| {
        points_out(
            &pts.iter()
                .copied()
                .filter(|p| p.ts >= cutoff)
                .collect::<Vec<_>>(),
        )
    };
    Ok(MetricsOut {
        cpu_pct: trim(&m.cpu_pct),
        net_in_bps: trim(&m.net_in_bps),
        net_out_bps: trim(&m.net_out_bps),
        disk_io: trim(&m.disk_io),
    })
}

/// Power a server on/off/reboot. Refuses to touch the node carrying the ACTIVE VPN tunnel —
/// that teardown path (kill switch, routes, wg) lives on the VPN screen.
#[tauri::command]
pub async fn servers_power(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    action: String,
) -> Result<(), String> {
    if provider == "linode" {
        let in_active_chain = {
            let g = state.inner.lock().unwrap();
            g.vpn
                .as_ref()
                .map(|v| v.instance_id == id || v.chain.contains(&id))
                .unwrap_or(false)
        };
        if in_active_chain {
            return Err(
                "This node is carrying your active VPN connection — disconnect or manage it \
                 from the VPN screen instead."
                    .into(),
            );
        }
    }
    let act = match action.as_str() {
        "start" => PowerAction::Boot,
        "stop" => PowerAction::Shutdown,
        "reboot" => PowerAction::Reboot,
        a => return Err(format!("unknown action: {a}")),
    };
    let mgr = manager_for(&provider)?;
    mgr.power(&id, act).await.map_err(|e| e.to_string())?;
    crate::applog::info(
        "servers.power",
        &format!("{provider}/{id}: {action} requested"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Stage 3: server lifecycle — snapshots, reverse DNS, delete-protection,
// activity feed, and a one-click SSH terminal. (Snapshot/rDNS/protection do NOT
// power-cycle the node, so the active-VPN guard on servers_power isn't needed here.)
// ---------------------------------------------------------------------------

/// Take a labelled snapshot/image of a server.
#[tauri::command]
pub async fn servers_snapshot(provider: String, id: String, label: String) -> Result<(), String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("Enter a name for the snapshot.".into());
    }
    if label.len() > 64 {
        return Err("Snapshot name is too long (max 64 characters).".into());
    }
    let mgr = manager_for(&provider)?;
    mgr.snapshot(&id, label).await.map_err(|e| e.to_string())?;
    crate::applog::info("servers.snapshot", &format!("{provider}/{id}: {label}"));
    Ok(())
}

/// List a server's snapshots, newest first.
#[tauri::command]
pub async fn servers_list_snapshots(
    provider: String,
    id: String,
) -> Result<Vec<SnapshotOut>, String> {
    let mgr = manager_for(&provider)?;
    let snaps = mgr.list_snapshots(&id).await.map_err(|e| e.to_string())?;
    Ok(snaps.into_iter().map(snapshot_out).collect())
}

/// Recent activity/actions for a server, newest first.
#[tauri::command]
pub async fn servers_events(provider: String, id: String) -> Result<Vec<ServerEventOut>, String> {
    let mgr = manager_for(&provider)?;
    let evs = mgr.recent_events(&id).await.map_err(|e| e.to_string())?;
    Ok(evs.into_iter().map(event_out).collect())
}

/// Set the reverse-DNS (PTR) record for a server's public IP.
#[tauri::command]
pub async fn servers_set_rdns(
    provider: String,
    id: String,
    ip: String,
    ptr: String,
) -> Result<(), String> {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err("That doesn't look like a valid IP address.".into());
    }
    let ptr = ptr.trim();
    if ptr.is_empty() || ptr.len() > 253 {
        return Err("Enter a valid hostname for the reverse-DNS record.".into());
    }
    let mgr = manager_for(&provider)?;
    mgr.set_rdns(&id, &ip, ptr).await.map_err(|e| e.to_string())
}

/// Turn delete/rebuild protection on or off (Hetzner; Linode reports not-supported).
#[tauri::command]
pub async fn servers_set_protection(provider: String, id: String, on: bool) -> Result<(), String> {
    let mgr = manager_for(&provider)?;
    mgr.set_protection(&id, on).await.map_err(|e| e.to_string())
}

/// Open an interactive terminal SSHed into the server as root. The window is VISIBLE on purpose
/// (no `CREATE_NO_WINDOW`). Windows tries Windows Terminal, then falls back to a PowerShell window.
/// Other platforms return a friendly message (the UI always shows a copy-paste `ssh` line too).
#[tauri::command]
pub fn servers_open_terminal(ip: String) -> Result<(), String> {
    let _parsed: std::net::IpAddr = ip
        .parse()
        .map_err(|_| "That doesn't look like a valid IP address.".to_string())?;
    #[cfg(target_os = "windows")]
    {
        let target = format!("root@{ip}");
        if std::process::Command::new("wt.exe")
            .args(["ssh", &target])
            .spawn()
            .is_ok()
        {
            Ok(())
        } else {
            std::process::Command::new("powershell")
                .args(["-NoExit", "-Command", &format!("ssh {target}")])
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("open terminal: {e}"))
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(
            "Open terminal is available in the Windows app — use the copy-paste SSH command below."
                .into(),
        )
    }
}

// ---------------------------------------------------------------------------
// Stage 2: per-server monitor config (servers-config.json), Netdata bridge
// commands, and the background watchdog with native-toast alerts.
// ---------------------------------------------------------------------------

const CONFIG_FILE: &str = "servers-config.json";

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase", default)]
pub struct WatchdogFileCfg {
    pub enabled: bool,
    pub interval_secs: u32,
    pub cpu_pct: f64,
    pub cpu_sustain_ticks: u32,
    pub disk_pct: f64,
}

impl Default for WatchdogFileCfg {
    fn default() -> Self {
        WatchdogFileCfg {
            enabled: false,
            interval_secs: 120,
            cpu_pct: 90.0,
            cpu_sustain_ticks: 3,
            disk_pct: 90.0,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase", default)]
pub struct NetdataFileCfg {
    pub enabled: bool,
    pub port: u16,
    pub https: bool,
    pub has_auth: bool,
}

impl Default for NetdataFileCfg {
    fn default() -> Self {
        NetdataFileCfg {
            enabled: false,
            port: 19999,
            https: false,
            has_auth: false,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
struct ServersFileCfg {
    watchdog: WatchdogFileCfg,
    /// Keyed by `"provider:id"`.
    netdata: BTreeMap<String, NetdataFileCfg>,
}

fn cfg_path(dir: &Path) -> PathBuf {
    dir.join(CONFIG_FILE)
}

fn load_cfg(dir: &Path) -> ServersFileCfg {
    std::fs::read_to_string(cfg_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_cfg(dir: &Path, cfg: &ServersFileCfg) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(
        cfg_path(dir),
        serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn data_dir(state: &State<'_, AppState>) -> PathBuf {
    state.inner.lock().unwrap().data_dir.clone()
}

fn netdata_key(provider: &str, id: &str) -> String {
    format!("{provider}:{id}")
}

fn netdata_auth_account(provider: &str, id: &str) -> String {
    format!("netdata-auth-{provider}-{id}")
}

/// Build the endpoint for one server from its stored config (+ keychain auth header).
fn endpoint_for(
    dir: &Path,
    provider: &str,
    id: &str,
    host: &str,
) -> (NetdataEndpoint, NetdataFileCfg) {
    let cfg = load_cfg(dir)
        .netdata
        .get(&netdata_key(provider, id))
        .copied()
        .unwrap_or_default();
    let auth_header = if cfg.has_auth {
        keyring::Entry::new(KC_SERVICE, &netdata_auth_account(provider, id))
            .ok()
            .and_then(|e| e.get_password().ok())
            .filter(|s| !s.trim().is_empty())
    } else {
        None
    };
    (
        NetdataEndpoint {
            https: cfg.https,
            host: host.to_string(),
            port: cfg.port,
            auth_header,
        },
        cfg,
    )
}

#[tauri::command]
pub fn servers_watchdog_get(state: State<AppState>) -> WatchdogFileCfg {
    load_cfg(&data_dir(&state)).watchdog
}

#[tauri::command]
pub fn servers_watchdog_set(state: State<AppState>, cfg: WatchdogFileCfg) -> Result<(), String> {
    let dir = data_dir(&state);
    let mut file = load_cfg(&dir);
    file.watchdog = cfg;
    save_cfg(&dir, &file)
}

#[tauri::command]
pub fn netdata_get(state: State<AppState>, provider: String, id: String) -> NetdataFileCfg {
    load_cfg(&data_dir(&state))
        .netdata
        .get(&netdata_key(&provider, &id))
        .copied()
        .unwrap_or_default()
}

/// Save one server's Netdata config. `auth_value`: `None` leaves the stored credential
/// untouched; `Some("")` clears it; `Some(v)` stores `v` as the raw Authorization header
/// value in the keychain (never in the JSON).
#[tauri::command]
pub fn netdata_set(
    state: State<AppState>,
    provider: String,
    id: String,
    cfg: NetdataFileCfg,
    auth_value: Option<String>,
) -> Result<(), String> {
    let dir = data_dir(&state);
    let mut file = load_cfg(&dir);
    let key = netdata_key(&provider, &id);
    let prev_has_auth = file.netdata.get(&key).map(|c| c.has_auth).unwrap_or(false);
    let mut stored = cfg;
    match auth_value {
        None => stored.has_auth = prev_has_auth,
        Some(v) => {
            let account = netdata_auth_account(&provider, &id);
            let entry = keyring::Entry::new(KC_SERVICE, &account).map_err(|e| e.to_string())?;
            if v.trim().is_empty() {
                let _ = entry.delete_credential();
                stored.has_auth = false;
            } else {
                entry.set_password(v.trim()).map_err(|e| e.to_string())?;
                stored.has_auth = true;
            }
        }
    }
    file.netdata.insert(key, stored);
    save_cfg(&dir, &file)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetdataProbeOut {
    reachable: bool,
    version: String,
    hostname: String,
    url: String,
    https: bool,
    error: Option<String>,
}

/// Try to reach a server's Netdata agent: the configured scheme first, then the other.
/// On success the working scheme is saved back to the config.
#[tauri::command]
pub async fn netdata_probe(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<NetdataProbeOut, String> {
    let dir = data_dir(&state);
    let (ep, cfg) = endpoint_for(&dir, &provider, &id, &host);
    let mut last_err = String::new();
    for https in [ep.https, !ep.https] {
        let try_ep = NetdataEndpoint {
            https,
            ..ep.clone()
        };
        match try_ep.info().await {
            Ok(info) => {
                // Persist the working scheme so future fetches skip the fallback.
                let mut file = load_cfg(&dir);
                file.netdata
                    .insert(netdata_key(&provider, &id), NetdataFileCfg { https, ..cfg });
                let _ = save_cfg(&dir, &file);
                return Ok(NetdataProbeOut {
                    reachable: true,
                    version: info.version,
                    hostname: info.hostname,
                    url: try_ep.base_url(),
                    https,
                    error: None,
                });
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Ok(NetdataProbeOut {
        reachable: false,
        version: String::new(),
        hostname: String::new(),
        url: ep.base_url(),
        https: ep.https,
        error: Some(last_err),
    })
}

/// One aggregated Netdata metric series, ready to chart. `kind`: cpu | ram | net | load | disk.
#[tauri::command]
pub async fn netdata_metric(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    kind: String,
    after_secs: u32,
    points: u32,
) -> Result<Vec<[f64; 2]>, String> {
    let dir = data_dir(&state);
    let (ep, _) = endpoint_for(&dir, &provider, &id, &host);
    let (chart, agg): (
        &str,
        fn(&netdata::NetdataSeries) -> Vec<sentinel_core::cloud::MetricPoint>,
    ) = match kind.as_str() {
        "cpu" => ("system.cpu", netdata::cpu_total_pct),
        "ram" => ("system.ram", netdata::ram_used_pct),
        "net" => ("system.net", netdata::net_total_bps),
        "load" => ("system.load", netdata::load1),
        // Netdata names the root-filesystem chart `disk_space./` (the mount point is part of the
        // id); the old `disk_space._` guess returns nothing on current agents.
        "disk" => ("disk_space./", netdata::disk_used_pct),
        k => return Err(format!("unknown metric kind: {k}")),
    };
    let series = ep
        .data(chart, after_secs.clamp(10, 86_400), points.clamp(2, 600))
        .await
        .map_err(|e| e.to_string())?;
    Ok(points_out(&agg(&series)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlarmOut {
    name: String,
    status: String,
    value: String,
}

#[tauri::command]
pub async fn netdata_alarms(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<Vec<AlarmOut>, String> {
    let dir = data_dir(&state);
    let (ep, _) = endpoint_for(&dir, &provider, &id, &host);
    Ok(ep
        .alarms_active()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|a| AlarmOut {
            name: a.name,
            status: a.status,
            value: a.value,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// the watchdog poller
// ---------------------------------------------------------------------------

/// One watchdog tick: list fleets, sample Netdata where enabled, evaluate, alert.
async fn watchdog_tick(
    app: &AppHandle,
    dir: &Path,
    file: &ServersFileCfg,
    wd: &mut watchdog::WatchdogState,
) {
    let mut samples: Vec<watchdog::ServerSample> = Vec::new();
    let mut providers_ok: Vec<&'static str> = Vec::new();

    let mut fleets: Vec<(&'static str, Vec<ServerInfo>)> = Vec::new();
    if let Some(token) = crate::vpn::get_token() {
        match ServerManager::list_all(&LinodeClient::new(token)).await {
            Ok(list) => {
                providers_ok.push("linode");
                fleets.push(("linode", list));
            }
            Err(e) => crate::applog::info("servers.watchdog", &format!("linode list failed: {e}")),
        }
    }
    if let Some(token) = hetzner_get_token() {
        match HetznerClient::new(token).list_all().await {
            Ok(list) => {
                providers_ok.push("hetzner");
                fleets.push(("hetzner", list));
            }
            Err(e) => crate::applog::info("servers.watchdog", &format!("hetzner list failed: {e}")),
        }
    }

    for (provider, list) in &fleets {
        for info in list {
            let key = netdata_key(provider, &info.id);
            let mut sample = watchdog::ServerSample {
                key: key.clone(),
                label: info.label.clone(),
                state: info.state,
                cpu_pct: None,
                disk_used_pct: None,
                netdata_alarms: None,
            };
            // Netdata deep-sample only where explicitly enabled and the server has an IP.
            let nd_enabled = file.netdata.get(&key).map(|c| c.enabled).unwrap_or(false);
            if nd_enabled {
                if let Some(host) = &info.ipv4 {
                    let (ep, _) = endpoint_for(dir, provider, &info.id, host);
                    if let Ok(s) = ep.data("system.cpu", 60, 4).await {
                        sample.cpu_pct = netdata::cpu_total_pct(&s).last().map(|p| p.value);
                    }
                    if let Ok(s) = ep.data("disk_space._", 60, 2).await {
                        sample.disk_used_pct = netdata::disk_used_pct(&s).last().map(|p| p.value);
                    }
                    if let Ok(alarms) = ep.alarms_active().await {
                        sample.netdata_alarms = Some(alarms.len() as u32);
                    }
                }
            }
            samples.push(sample);
        }
    }

    let cfg = watchdog::WatchdogCfg {
        cpu_pct: file.watchdog.cpu_pct,
        cpu_sustain_ticks: file.watchdog.cpu_sustain_ticks.max(1),
        disk_pct: file.watchdog.disk_pct,
    };
    for alert in watchdog::evaluate(wd, &samples, &providers_ok, &cfg) {
        let (kind, key, label) = match &alert {
            watchdog::Alert::Down { key, label } => ("down", key, label),
            watchdog::Alert::Recovered { key, label } => ("recovered", key, label),
            watchdog::Alert::CpuHigh { key, label, .. } => ("cpu", key, label),
            watchdog::Alert::DiskHigh { key, label, .. } => ("disk", key, label),
            watchdog::Alert::NetdataAlarm { key, label, .. } => ("netdata", key, label),
        };
        let message = alert.message();
        crate::applog::info("servers.alert", &message);
        let _ = app.emit(
            "servers:alert",
            serde_json::json!({
                "kind": kind,
                "key": key,
                "label": label,
                "message": message,
                "ts": time::OffsetDateTime::now_utc().unix_timestamp(),
            }),
        );
        // Native toast (Windows). Failures are non-fatal — the in-app feed + log always get it.
        use tauri_plugin_notification::NotificationExt;
        let _ = app
            .notification()
            .builder()
            .title("NorthKey — server alert")
            .body(&message)
            .show();
    }
}

/// Background watchdog: self-gating loop (config re-read every tick, like the VPN
/// auto-connect poller). Alerts only while the app runs — stated in the UI.
pub fn spawn_servers_watchdog(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut wd = watchdog::WatchdogState::default();
        loop {
            let dir = {
                let s = app.state::<AppState>();
                let d = s.inner.lock().unwrap().data_dir.clone();
                d
            };
            let file = load_cfg(&dir);
            if file.watchdog.enabled {
                watchdog_tick(&app, &dir, &file, &mut wd).await;
            }
            let sleep_secs = file.watchdog.interval_secs.clamp(60, 3600) as u64;
            tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
        }
    });
}
