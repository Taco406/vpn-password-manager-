//! Real VPN backend (Stage 2, opt-in): ephemeral Linode exit nodes + a WireGuard tunnel.
//!
//! This is active ONLY when the user has stored a Linode API token (Settings → VPN). With no
//! token, the frontend keeps using the in-browser simulation, so this path can never touch a
//! user who hasn't opted in. Safety: `sentinel_core::vpn::connect` guarantees the instance is
//! destroyed on any failure edge, an orphan-sweep runs on launch, and each node arms a
//! dead-man switch — so bugs can't leave a paid server running silently.
//!
//! Three pieces the core left to the platform layer live here: a real client-side WireGuard
//! controller (drives the OS WireGuard), a real HTTP pubkey-callback fetcher, and Linode-token
//! storage in the OS keychain.

use crate::state::AppState;
use async_trait::async_trait;
use sentinel_core::cloud::{InstanceSpec, InstanceState, LinodeClient};
use sentinel_core::error::{CoreError, Result as CoreResult};
use sentinel_core::provision::{
    render_base64, verify_callback, CallbackBody, CloudInitParams, NextHop,
};
use sentinel_core::vpn::{
    connect as core_connect, disconnect as core_disconnect, orphan_sweep_keeping, ConnectDeps,
    ConnectState, ServerPubkeyFetcher,
};
use sentinel_core::vpn::{CostTicker, HistoryStore, SessionRecord};
use sentinel_core::wg::{
    full_tunnel, render_client_conf, ClientConf, WgController, WgCounters, WgKeypair,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

const KC_SERVICE: &str = "com.sentinel.desktop";
const KC_LINODE: &str = "linode-token";
const TUNNEL: &str = "sentinel";

// --- kill switch + auto-connect (all opt-in, only meaningful in real-VPN mode) ------------
/// Shared name+group tag for every kill-switch firewall rule, so the whole set can be torn
/// down in one command (delete-by-name is the reliable path; group is set too). Changing
/// this string orphans old rules — keep it stable.
#[cfg_attr(not(windows), allow(dead_code))]
const KILLSWITCH_ID: &str = "SENTINEL-KillSwitch";
/// WireGuard UDP port the exit node listens on (matches the hardened cloud-init firewall).
#[cfg_attr(not(windows), allow(dead_code))]
const WG_PORT: &str = "51820";
/// Cheapest node — what an automatic (untrusted-Wi-Fi) connect provisions by default.
const DEFAULT_INSTANCE_TYPE: &str = "g6-nanode-1";
/// How often the untrusted-Wi-Fi poller checks the current SSID.
const AUTOCONNECT_POLL_SECS: u64 = 30;
/// After a manual disconnect, suppress auto-connect for this long so we never immediately
/// fight the user's choice to go off-VPN.
const AUTOCONNECT_DEBOUNCE_SECS: i64 = 300;

/// Unix time of the last manual `vpn_disconnect` (0 = never), used for the auto-connect
/// debounce above.
static LAST_MANUAL_DISCONNECT: AtomicI64 = AtomicI64::new(0);
/// Guards against two overlapping connect attempts (manual + auto racing), which would
/// otherwise provision two paid nodes.
static CONNECTING: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Linode token in the OS keychain
// ---------------------------------------------------------------------------

pub fn get_token() -> Option<String> {
    let entry = keyring::Entry::new(KC_SERVICE, KC_LINODE).ok()?;
    entry
        .get_password()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn set_token(token: &str) -> std::result::Result<(), String> {
    let entry = keyring::Entry::new(KC_SERVICE, KC_LINODE).map_err(|e| e.to_string())?;
    if token.trim().is_empty() {
        let _ = entry.delete_credential();
        Ok(())
    } else {
        entry.set_password(token.trim()).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// region + instance-type catalogs (valid Linode ids + globe coordinates)
// ---------------------------------------------------------------------------

struct RegionRow {
    id: &'static str,
    label: &'static str,
    country: &'static str,
    lat: f64,
    lon: f64,
    /// Per-region Linode speedtest mirror, used only for a best-effort TCP-connect latency
    /// probe (never for the tunnel itself). If it doesn't resolve, latency is simply omitted.
    speedtest_host: &'static str,
}

// Linode region ids (valid for `create`) with coordinates for the globe.
const REGIONS: &[RegionRow] = &[
    RegionRow {
        id: "us-east",
        label: "Newark, NJ",
        country: "US",
        lat: 40.74,
        lon: -74.17,
        speedtest_host: "speedtest.newark.linode.com",
    },
    RegionRow {
        id: "us-central",
        label: "Dallas, TX",
        country: "US",
        lat: 32.78,
        lon: -96.80,
        speedtest_host: "speedtest.dallas.linode.com",
    },
    RegionRow {
        id: "us-west",
        label: "Fremont, CA",
        country: "US",
        lat: 37.55,
        lon: -121.98,
        speedtest_host: "speedtest.fremont.linode.com",
    },
    RegionRow {
        id: "us-southeast",
        label: "Atlanta, GA",
        country: "US",
        lat: 33.75,
        lon: -84.39,
        speedtest_host: "speedtest.atlanta.linode.com",
    },
    RegionRow {
        id: "ca-central",
        label: "Toronto",
        country: "CA",
        lat: 43.65,
        lon: -79.38,
        speedtest_host: "speedtest.toronto1.linode.com",
    },
    RegionRow {
        id: "eu-west",
        label: "London",
        country: "GB",
        lat: 51.51,
        lon: -0.13,
        speedtest_host: "speedtest.london.linode.com",
    },
    RegionRow {
        id: "eu-central",
        label: "Frankfurt",
        country: "DE",
        lat: 50.11,
        lon: 8.68,
        speedtest_host: "speedtest.frankfurt.linode.com",
    },
    RegionRow {
        id: "ap-south",
        label: "Singapore",
        country: "SG",
        lat: 1.35,
        lon: 103.82,
        speedtest_host: "speedtest.singapore.linode.com",
    },
    RegionRow {
        id: "ap-northeast",
        label: "Tokyo",
        country: "JP",
        lat: 35.68,
        lon: 139.69,
        speedtest_host: "speedtest.tokyo2.linode.com",
    },
    RegionRow {
        id: "ap-southeast",
        label: "Sydney",
        country: "AU",
        lat: -33.87,
        lon: 151.21,
        speedtest_host: "speedtest.syd1.linode.com",
    },
];

struct TypeRow {
    id: &'static str,
    label: &'static str,
    vcpus: u32,
    memory_mb: u32,
    hourly_usd: f64,
}

const INSTANCE_TYPES: &[TypeRow] = &[
    TypeRow {
        id: "g6-nanode-1",
        label: "Nanode 1GB",
        vcpus: 1,
        memory_mb: 1024,
        hourly_usd: 0.0075,
    },
    TypeRow {
        id: "g6-standard-2",
        label: "Linode 4GB",
        vcpus: 2,
        memory_mb: 4096,
        hourly_usd: 0.036,
    },
    TypeRow {
        id: "g6-standard-4",
        label: "Linode 8GB",
        vcpus: 4,
        memory_mb: 8192,
        hourly_usd: 0.072,
    },
    TypeRow {
        id: "g6-dedicated-4",
        label: "Dedicated 8GB",
        vcpus: 4,
        memory_mb: 8192,
        hourly_usd: 0.108,
    },
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionOut {
    id: String,
    label: String,
    country: String,
    lat: f64,
    lon: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<u32>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeOut {
    id: String,
    label: String,
    vcpus: u32,
    memory_mb: u32,
    hourly_usd: f64,
}

fn hourly_for(instance_type: &str) -> f64 {
    INSTANCE_TYPES
        .iter()
        .find(|t| t.id == instance_type)
        .map(|t| t.hourly_usd)
        .unwrap_or(0.0075)
}

// ---------------------------------------------------------------------------
// real client-side WireGuard controller (drives the OS WireGuard)
// ---------------------------------------------------------------------------

/// Drives the OS WireGuard: on Windows the official `wireguard.exe` tunnel service, on
/// unix `wg-quick`. `wg`/`wireguard.exe` paths are overridable via env for testing.
pub struct SystemWgController {
    conf_path: PathBuf,
}

impl SystemWgController {
    pub fn new() -> Self {
        SystemWgController {
            conf_path: std::env::temp_dir().join(format!("{TUNNEL}.conf")),
        }
    }
}

fn wg_bin() -> String {
    std::env::var("SENTINEL_WG_EXE").unwrap_or_else(|_| {
        if cfg!(windows) {
            r"C:\Program Files\WireGuard\wg.exe".to_string()
        } else {
            "wg".to_string()
        }
    })
}
fn wireguard_bin() -> String {
    std::env::var("SENTINEL_WIREGUARD_EXE")
        .unwrap_or_else(|_| r"C:\Program Files\WireGuard\wireguard.exe".to_string())
}

/// Where to send users who don't have WireGuard yet.
pub const WG_DOWNLOAD_URL: &str = "https://www.wireguard.com/install/";

/// First matching `bin` found on `PATH`, if any (used for the unix WireGuard check).
fn which_on_path(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand.to_string_lossy().to_string());
        }
    }
    None
}

/// Whether the OS WireGuard tooling is installed, and the path/command we found (for display).
/// Honors the `SENTINEL_WIREGUARD_EXE` / `SENTINEL_WG_EXE` overrides used in dev/tests.
fn wireguard_installed() -> (bool, Option<String>) {
    if cfg!(windows) {
        for cand in [wireguard_bin(), wg_bin()] {
            if std::path::Path::new(&cand).exists() {
                return (true, Some(cand));
            }
        }
        (false, None)
    } else {
        let wg = wg_bin();
        if std::path::Path::new(&wg).is_absolute() && std::path::Path::new(&wg).is_file() {
            return (true, Some(wg));
        }
        for bin in ["wg-quick", "wg"] {
            if let Some(p) = which_on_path(bin) {
                return (true, Some(p));
            }
        }
        (false, None)
    }
}

/// Whether SENTINEL is running elevated. Installing a WireGuard tunnel *service* on Windows
/// requires Administrator; `net session` succeeds only when elevated (a standard, dependency-free
/// probe). Non-Windows isn't gated on this here (the unix path uses `wg-quick` under sudo/root).
fn is_elevated() -> bool {
    if cfg!(windows) {
        std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        true
    }
}

/// Live status of the local WireGuard prerequisites, for the Settings "WireGuard" monitor.
#[derive(serde::Serialize)]
pub struct WgStatus {
    /// The `wireguard.exe` / `wg` tooling is present.
    pub installed: bool,
    /// The path we detected it at (or `None`).
    pub path: Option<String>,
    /// SENTINEL is running as Administrator (Windows) — required to bring the tunnel up.
    pub elevated: bool,
    /// True on Windows, where elevation actually matters (the UI hides the admin row elsewhere).
    pub elevation_matters: bool,
    /// Where to download WireGuard if it's missing.
    pub download_url: String,
}

/// Report whether WireGuard is installed and whether we're elevated (for the monitor + pre-flight).
#[tauri::command]
pub fn wg_status() -> WgStatus {
    let (installed, path) = wireguard_installed();
    WgStatus {
        installed,
        path,
        elevated: is_elevated(),
        elevation_matters: cfg!(windows),
        download_url: WG_DOWNLOAD_URL.to_string(),
    }
}

/// Open an http(s) URL in the default browser (the "Download WireGuard" button).
#[tauri::command]
pub fn open_url(url: String) -> std::result::Result<(), String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("refusing to open a non-http URL".into());
    }
    #[cfg(target_os = "windows")]
    let cmd = "explorer";
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = "xdg-open";
    std::process::Command::new(cmd)
        .arg(&url)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("open url: {e}"))
}

/// Emergency recovery: remove any leftover SENTINEL WireGuard tunnel and clear kill-switch rules,
/// to restore normal internet if a failed connect left the PC routing into a dead full-tunnel.
/// Best-effort and safe to run any time — a no-op when nothing is stuck.
#[tauri::command]
pub async fn vpn_repair_tunnel() -> std::result::Result<(), String> {
    let _ = SystemWgController::new().down().await;
    killswitch_clear_all();
    crate::applog::info(
        "vpn.repair",
        "removed leftover tunnel + cleared kill-switch rules",
    );
    Ok(())
}

/// Fail fast — before we create a paid Linode — if the local WireGuard prerequisites are missing,
/// so the user fixes them instead of watching a node spin up and then die at the tunnel step.
fn preflight_vpn() -> std::result::Result<(), String> {
    if !wireguard_installed().0 {
        return Err(format!(
            "WireGuard isn't installed on this PC, so the tunnel can't come up. Install it from \
             {WG_DOWNLOAD_URL} (on Windows, then launch SENTINEL as Administrator) and try Connect \
             again — no server was created."
        ));
    }
    if cfg!(windows) && !is_elevated() {
        return Err(
            "SENTINEL needs to run as Administrator to create the WireGuard tunnel. Close SENTINEL, \
             right-click it, choose \"Run as administrator\", then Connect again — no server was created."
                .into(),
        );
    }
    Ok(())
}

fn wg_err(detail: impl Into<String>) -> CoreError {
    CoreError::Provision {
        stage: "wg",
        detail: detail.into(),
    }
}

async fn run(program: &str, args: &[&str]) -> CoreResult<String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| wg_err(format!("spawn {program}: {e}")))?;
    if !out.status.success() {
        return Err(wg_err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

impl SystemWgController {
    /// Latest-handshake unix timestamp for the tunnel, 0 if none yet.
    async fn latest_handshake(&self) -> u64 {
        let out = run(&wg_bin(), &["show", TUNNEL, "latest-handshakes"])
            .await
            .unwrap_or_default();
        out.split_whitespace()
            .last()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }
}

#[async_trait]
impl WgController for SystemWgController {
    async fn up(&self, conf: &ClientConf) -> CoreResult<()> {
        let text = render_client_conf(conf);
        std::fs::write(&self.conf_path, text).map_err(|e| wg_err(format!("write conf: {e}")))?;
        let path = self.conf_path.to_string_lossy().to_string();

        if cfg!(windows) {
            if let Err(e) = run(&wireguard_bin(), &["/installtunnelservice", &path]).await {
                // Installing a Windows tunnel service needs elevation; the raw error is a cryptic
                // "Access is denied". Translate it into something the user can act on.
                let es = e.to_string();
                if es.contains("Access is denied") || es.contains("denied") {
                    return Err(wg_err(
                        "SENTINEL must run as Administrator to create the WireGuard tunnel. \
                         Close SENTINEL, right-click it, choose \"Run as administrator\", then Connect again.",
                    ));
                }
                return Err(e);
            }
        } else {
            run("wg-quick", &["up", &path]).await?;
        }

        // Consider the tunnel "up" only once a real handshake lands (so "Connected" never lies).
        // Poll ~120s — the server's wg0 + first handshake can take longer than a minute on a
        // fresh node.
        for _ in 0..60 {
            if self.latest_handshake().await > 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        // CRITICAL: a full-tunnel config routes ALL traffic through this interface. If the
        // handshake never lands we must remove the tunnel before returning, or the PC is left
        // routing everything into a dead tunnel — i.e. no internet — until the user removes it
        // by hand. Tear it down first, then fail.
        let _ = self.down().await;
        Err(wg_err(
            "no WireGuard handshake within 120s — the exit node didn't answer. The tunnel was \
             removed so your internet is restored; please try Connect again.",
        ))
    }

    async fn down(&self) -> CoreResult<()> {
        let path = self.conf_path.to_string_lossy().to_string();
        let res = if cfg!(windows) {
            run(&wireguard_bin(), &["/uninstalltunnelservice", TUNNEL]).await
        } else {
            run("wg-quick", &["down", &path]).await
        };
        let _ = std::fs::remove_file(&self.conf_path);
        res.map(|_| ())
    }

    async fn counters(&self, _elapsed_secs: f64) -> CoreResult<WgCounters> {
        let transfer = run(&wg_bin(), &["show", TUNNEL, "transfer"])
            .await
            .unwrap_or_default();
        // "<pubkey>\t<rx>\t<tx>"
        let mut cols = transfer.split_whitespace();
        let _pk = cols.next();
        let rx_bytes = cols.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let tx_bytes = cols.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let hs = self.latest_handshake().await;
        let now = now_secs() as u64;
        let last_handshake_secs = if hs == 0 { 0 } else { now.saturating_sub(hs) };
        Ok(WgCounters {
            rx_bytes,
            tx_bytes,
            last_handshake_secs,
        })
    }
}

// ---------------------------------------------------------------------------
// real pubkey-callback fetcher
// ---------------------------------------------------------------------------

pub struct HttpPubkeyFetcher {
    http: reqwest::Client,
}
impl HttpPubkeyFetcher {
    pub fn new() -> Self {
        HttpPubkeyFetcher {
            http: reqwest::Client::builder()
                // The responder calls out to ipify to learn its own IP, so a single request can
                // take ~10s once it's up; keep the client timeout above that.
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl ServerPubkeyFetcher for HttpPubkeyFetcher {
    async fn fetch(&self, ip: &str, token: &str, hmac_key_hex: &str) -> CoreResult<String> {
        let url = format!("http://{ip}:443/");
        let mut last = String::from("no response");
        // The node may still be running cloud-init (apt update + install wireguard-tools) before
        // its responder listens — that can take a few minutes on a fresh Linode. Retry ~90×2s ≈
        // 3 min (plus per-request time) so a slow provision doesn't fail a connect that would work.
        for _ in 0..90 {
            match self.http.get(&url).bearer_auth(token).send().await {
                Ok(resp) if resp.status().is_success() => match resp.json::<CallbackBody>().await {
                    Ok(body) => return verify_callback(&body, hmac_key_hex),
                    Err(e) => last = format!("bad callback json: {e}"),
                },
                Ok(resp) => last = format!("callback HTTP {}", resp.status()),
                Err(e) => last = format!("callback request: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(CoreError::Provision {
            stage: "callback",
            detail: format!("server pubkey not retrieved: {last}"),
        })
    }
}

// ---------------------------------------------------------------------------
// live session state
// ---------------------------------------------------------------------------

pub struct VpnActive {
    pub deps: ConnectDeps,
    /// The entry node's instance id (the one the local tunnel connects to).
    pub instance_id: String,
    /// Every node id in the path, entry-first. Single-hop = `[instance_id]`; multi-hop lists
    /// all hops so disconnect destroys the whole chain (money-critical — no orphan hops).
    pub chain: Vec<String>,
    pub region: String,
    pub instance_type: String,
    pub egress_ip: Option<String>,
    pub started_at: i64,
    pub stop: Arc<AtomicBool>,
}

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn live_deps(token: String) -> ConnectDeps {
    ConnectDeps {
        cloud: Arc::new(LinodeClient::new(token)),
        wg: Arc::new(SystemWgController::new()),
        fetcher: Arc::new(HttpPubkeyFetcher::new()),
        // A real Linode reaches Running in ~1 min, so poll every 3s up to 60 times (3 min cap).
        // Without a delay the loop would burn all 60 polls in seconds and wrongly time out at boot.
        max_boot_polls: 60,
        poll_interval_ms: 3000,
    }
}

fn state_json(s: &ConnectState, region: &str, instance_type: &str) -> serde_json::Value {
    let (stage, detail, egress): (&str, String, Option<String>) = match s {
        ConnectState::Idle => ("idle", String::new(), None),
        ConnectState::CreatingInstance => {
            ("creatingInstance", "Provisioning exit node…".into(), None)
        }
        ConnectState::Booting => ("booting", "Booting server…".into(), None),
        ConnectState::ExchangingKeys => ("exchangingKeys", "Exchanging keys…".into(), None),
        ConnectState::StartingTunnel => ("startingTunnel", "Bringing the tunnel up…".into(), None),
        ConnectState::Connected { egress_ip, .. } => {
            ("connected", "Secured".into(), egress_ip.clone())
        }
        ConnectState::Disconnecting => ("disconnecting", "Disconnecting…".into(), None),
        ConnectState::Destroying => ("destroying", "Destroying exit node…".into(), None),
        ConnectState::Failed { reason, .. } => ("failed", reason.clone(), None),
    };
    json!({
        "stage": stage,
        "region": region,
        "instanceType": instance_type,
        "detail": detail,
        "egressIp": egress,
    })
}

// ---------------------------------------------------------------------------
// kill switch (Windows-only firewall, opt-in) — SAFETY: never leave traffic blocked
// ---------------------------------------------------------------------------
//
// Every rule shares the same name AND group `SENTINEL-KillSwitch`, so the whole set is
// removable in one command. The block is fail-closed: if anything goes wrong the traffic is
// blocked (safe) rather than leaked, and four independent paths guarantee the block is always
// removed — on disconnect, on any connect failure, on every launch, and on app exit — plus a
// manual `killswitch_clear` panic button. So a bug can never permanently strand the user
// offline. It is a no-op on non-Windows (WireGuard there uses `wg-quick`, out of scope here).

/// Run a `netsh` command, hiding the console window on Windows. Returns the trimmed stderr on
/// failure so the caller can log it. Only compiled on Windows.
#[cfg(windows)]
fn netsh(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("spawn netsh: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "netsh {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Remove ALL kill-switch firewall rules. Idempotent and best-effort: a missing rule set is
/// not an error. This is THE safety guarantee — after this returns, nothing in our group can
/// still be blocking traffic. No-op off Windows.
pub fn killswitch_clear_all() {
    #[cfg(windows)]
    {
        // Reliable path: all our rules share this exact name, so one delete removes them all.
        let _ = netsh(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={KILLSWITCH_ID}"),
        ]);
        // Belt-and-suspenders: also try the group form (harmless if unsupported).
        let _ = netsh(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("group={KILLSWITCH_ID}"),
        ]);
    }
}

/// Engage the kill switch for a freshly-established tunnel whose exit node is `endpoint_ip`.
/// Adds a block-all-outbound rule plus carve-outs for the tunnel handshake, the WireGuard
/// service, loopback and the local subnet. Windows only.
#[cfg(windows)]
fn killswitch_engage(endpoint_ip: &str) -> Result<(), String> {
    // Start clean so we never stack stale/duplicate rules.
    killswitch_clear_all();

    let name = format!("name={KILLSWITCH_ID}");
    let group = format!("group={KILLSWITCH_ID}");

    // Allow carve-outs first (organisational; precedence is enforced by Windows, not order).
    // Loopback.
    netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name,
        &group,
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        "remoteip=127.0.0.0/8",
    ])?;
    // Local/LAN, DHCP, link-local and multicast so the LAN keeps working under the block.
    netsh(&[
        "advfirewall", "firewall", "add", "rule", &name, &group, "dir=out", "action=allow",
        "enable=yes", "profile=any",
        "remoteip=LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4,255.255.255.255",
    ])?;
    // The WireGuard handshake/keepalive to the exit node (so the tunnel itself can connect).
    if !endpoint_ip.is_empty() {
        let remoteip = format!("remoteip={endpoint_ip}");
        let remoteport = format!("remoteport={WG_PORT}");
        netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name,
            &group,
            "dir=out",
            "action=allow",
            "enable=yes",
            "profile=any",
            "protocol=UDP",
            &remoteip,
            &remoteport,
        ])?;
    }
    // The WireGuard tunnel-service adapter, so traffic that egresses via the tunnel is allowed.
    let _ = netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name,
        &group,
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        &format!("service=WireGuardTunnel${TUNNEL}"),
    ]);

    // The safety net: block everything else outbound. Fail-closed — anything not carved out
    // above is blocked rather than leaked.
    netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name,
        &group,
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
        "remoteip=any",
    ])?;
    Ok(())
}

/// Engage the kill switch (Windows) or no-op (elsewhere).
#[cfg(windows)]
fn killswitch_engage_for(endpoint_ip: &str) -> Result<(), String> {
    killswitch_engage(endpoint_ip)
}
#[cfg(not(windows))]
fn killswitch_engage_for(_endpoint_ip: &str) -> Result<(), String> {
    Ok(())
}

/// Whether the kill switch should engage on connect. Reuses the existing `killSwitchDefault`
/// setting (the "Kill switch on by default" toggle). Absent ⇒ off, so we never engage a
/// traffic-blocking rule unless the user's persisted settings explicitly ask for it.
fn killswitch_enabled(data_dir: &Path) -> bool {
    std::fs::read_to_string(data_dir.join("settings.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get("killSwitchDefault").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// Manual panic button: tear down every kill-switch rule immediately. Always succeeds.
#[tauri::command]
pub fn killswitch_clear() -> Result<(), String> {
    killswitch_clear_all();
    Ok(())
}

// ---------------------------------------------------------------------------
// auto-connect on untrusted Wi-Fi (opt-in) + SSID detection
// ---------------------------------------------------------------------------

/// The current Wi-Fi SSID via `netsh wlan show interfaces`, or `None` if not on Wi-Fi / not
/// Windows. Parses the `SSID` line (guarding against the `BSSID` line).
#[cfg(windows)]
fn current_ssid() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        // Match a line that begins with "SSID" followed by spacing/colon, not "BSSID".
        if let Some(rest) = line.strip_prefix("SSID") {
            if !rest.starts_with(|c: char| c.is_whitespace() || c == ':') {
                continue;
            }
            if let Some((_, val)) = rest.split_once(':') {
                let val = val.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}
#[cfg(not(windows))]
fn current_ssid() -> Option<String> {
    None
}

struct NetSettings {
    auto_connect: bool,
    trusted: Vec<String>,
    default_region: String,
}

fn read_net_settings(data_dir: &Path) -> NetSettings {
    let v = std::fs::read_to_string(data_dir.join("settings.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| json!({}));
    NetSettings {
        auto_connect: v
            .get("autoConnectUntrusted")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        trusted: v
            .get("ssidAllowlist")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        default_region: v
            .get("defaultRegion")
            .and_then(|s| s.as_str())
            .unwrap_or("us-east")
            .to_string(),
    }
}

fn ssid_is_trusted(ssid: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|t| t.eq_ignore_ascii_case(ssid))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetStatus {
    /// `null` when not on Wi-Fi (or off Windows); always present so the UI shape is stable.
    ssid: Option<String>,
    trusted: bool,
    auto_connect: bool,
}

#[tauri::command]
pub fn net_status(state: State<AppState>) -> NetStatus {
    let data_dir = { state.inner.lock().unwrap().data_dir.clone() };
    let cfg = read_net_settings(&data_dir);
    let ssid = current_ssid();
    let trusted = ssid
        .as_ref()
        .map(|s| ssid_is_trusted(s, &cfg.trusted))
        .unwrap_or(false);
    NetStatus {
        ssid,
        trusted,
        auto_connect: cfg.auto_connect,
    }
}

/// Persist the auto-connect toggle + trusted-SSID list (read-merge-write, mirroring
/// `hello_set`, so unrelated settings are preserved). Trusted SSIDs live in `ssidAllowlist`.
#[tauri::command]
pub fn net_set(
    state: State<AppState>,
    auto_connect: bool,
    trusted_ssids: Vec<String>,
) -> Result<(), String> {
    let data_dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = data_dir.join("settings.json");
    let mut cur = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = cur.as_object_mut() {
        obj.insert(
            "autoConnectUntrusted".into(),
            serde_json::Value::Bool(auto_connect),
        );
        let cleaned: Vec<serde_json::Value> = trusted_ssids
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(serde_json::Value::String)
            .collect();
        obj.insert("ssidAllowlist".into(), serde_json::Value::Array(cleaned));
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&cur).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())
}

/// One tick of the untrusted-Wi-Fi poller. Auto-connects only when: the feature is on, real
/// VPN is configured, we're on Wi-Fi whose SSID is NOT trusted, nothing is already connected,
/// and we're outside the post-manual-disconnect debounce window.
async fn autoconnect_tick(app: &AppHandle) {
    let state = app.state::<AppState>();
    let data_dir = { state.inner.lock().unwrap().data_dir.clone() };
    let cfg = read_net_settings(&data_dir);
    if !cfg.auto_connect {
        return;
    }
    if get_token().is_none() {
        return; // real VPN not configured — never touch a non-opted-in user
    }
    if state.inner.lock().unwrap().vpn.is_some() {
        return; // already connected
    }
    let last = LAST_MANUAL_DISCONNECT.load(Ordering::Relaxed);
    if last > 0 && now_secs() - last < AUTOCONNECT_DEBOUNCE_SECS {
        return; // don't fight a recent manual disconnect
    }
    let Some(ssid) = current_ssid() else {
        return; // not on Wi-Fi (wired / no adapter)
    };
    if ssid_is_trusted(&ssid, &cfg.trusted) {
        return; // trusted network — leave it alone
    }
    // Untrusted Wi-Fi and idle: connect to the default region on the cheapest node.
    let _ = connect_real(
        app.clone(),
        &state,
        cfg.default_region,
        DEFAULT_INSTANCE_TYPE.to_string(),
    )
    .await;
}

/// Spawn the background untrusted-Wi-Fi poller (called once from setup). Cheap and self-gating
/// — every tick re-reads settings, so toggling the feature takes effect without a restart.
pub fn spawn_autoconnect_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(AUTOCONNECT_POLL_SECS)).await;
            autoconnect_tick(&app).await;
        }
    });
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnConfig {
    real_enabled: bool,
}

#[tauri::command]
pub fn vpn_config() -> VpnConfig {
    VpnConfig {
        real_enabled: get_token().is_some(),
    }
}

#[tauri::command]
pub fn vpn_set_token(token: String) -> std::result::Result<(), String> {
    set_token(&token)
}

/// Best-effort TCP-connect latency to a host with a tight timeout. On any failure (DNS,
/// refused, timeout) returns `None` so a flaky probe never blocks or poisons the list.
async fn measure_latency(host: &'static str) -> Option<u32> {
    let addr = format!("{host}:443");
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_millis(1000),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_stream)) => Some(start.elapsed().as_millis().min(u32::MAX as u128) as u32),
        _ => None,
    }
}

#[tauri::command]
pub async fn vpn_regions_real() -> Vec<RegionOut> {
    // Probe every region concurrently; each is capped at 1s, so the whole call stays ~1s
    // even when several hosts are unreachable. A failed probe just omits `latencyMs`.
    let mut set = tokio::task::JoinSet::new();
    for (i, r) in REGIONS.iter().enumerate() {
        let host = r.speedtest_host;
        set.spawn(async move { (i, measure_latency(host).await) });
    }
    let mut latencies: Vec<Option<u32>> = vec![None; REGIONS.len()];
    while let Some(res) = set.join_next().await {
        if let Ok((i, ms)) = res {
            if let Some(slot) = latencies.get_mut(i) {
                *slot = ms;
            }
        }
    }

    REGIONS
        .iter()
        .enumerate()
        .map(|(i, r)| RegionOut {
            id: r.id.into(),
            label: r.label.into(),
            country: r.country.into(),
            lat: r.lat,
            lon: r.lon,
            latency_ms: latencies.get(i).copied().flatten(),
        })
        .collect()
}

#[tauri::command]
pub fn vpn_instance_types_real() -> Vec<TypeOut> {
    INSTANCE_TYPES
        .iter()
        .map(|t| TypeOut {
            id: t.id.into(),
            label: t.label.into(),
            vcpus: t.vcpus,
            memory_mb: t.memory_mb,
            hourly_usd: t.hourly_usd,
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostOut {
    hourly_usd: f64,
    accrued_usd: f64,
}

#[tauri::command]
pub fn vpn_cost_estimate(state: State<AppState>) -> CostOut {
    let inner = state.inner.lock().unwrap();
    match &inner.vpn {
        Some(v) => {
            let hourly = hourly_for(&v.instance_type);
            CostOut {
                hourly_usd: hourly,
                accrued_usd: CostTicker::new(hourly, v.started_at).accrued(now_secs()),
            }
        }
        None => CostOut {
            hourly_usd: 0.0,
            accrued_usd: 0.0,
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateOut {
    stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_ip: Option<String>,
}

#[tauri::command]
pub fn vpn_state(state: State<AppState>) -> StateOut {
    let inner = state.inner.lock().unwrap();
    match &inner.vpn {
        Some(v) => StateOut {
            stage: "connected".into(),
            region: Some(v.region.clone()),
            instance_type: Some(v.instance_type.clone()),
            egress_ip: v.egress_ip.clone(),
        },
        None => StateOut {
            stage: "idle".into(),
            region: None,
            instance_type: None,
            egress_ip: None,
        },
    }
}

fn history_store(state: &State<AppState>) -> CoreResult<HistoryStore> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = dir.join("vpn-history.db");
    HistoryStore::open(&path.to_string_lossy())
}

/// Resets the `CONNECTING` guard on every exit path (including `?`/early return).
struct ConnectingGuard;
impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        CONNECTING.store(false, Ordering::SeqCst);
    }
}

#[tauri::command]
pub async fn vpn_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    region: String,
    instance_type: String,
) -> std::result::Result<(), String> {
    let r = connect_real(app, &state, region.clone(), instance_type).await;
    if let Err(e) = &r {
        crate::applog::error("vpn.connect", &format!("region {region}: {e}"));
    }
    r
}

/// The shared connect path used by both the manual `vpn_connect` command and the
/// untrusted-Wi-Fi auto-connect poller. Takes `&AppState` (not the Tauri extractor) so the
/// poller — which gets its state via `app.state()` — can call it too.
pub async fn connect_real(
    app: AppHandle,
    state: &AppState,
    region: String,
    instance_type: String,
) -> std::result::Result<(), String> {
    // Never provision two nodes from overlapping attempts (manual + auto racing).
    if CONNECTING.swap(true, Ordering::SeqCst) {
        return Err("a connection attempt is already in progress".into());
    }
    let _connecting = ConnectingGuard;

    if state.inner.lock().unwrap().vpn.is_some() {
        return Err("already connected".into());
    }
    // Check the local WireGuard prerequisites BEFORE spending money on a Linode.
    preflight_vpn()?;
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let deps = live_deps(token);

    let data_dir = { state.inner.lock().unwrap().data_dir.clone() };
    // Reap orphaned nodes before creating a new one — but keep any the user deliberately kept
    // (registry), so connecting doesn't destroy their saved/stopped nodes.
    let _ = orphan_sweep_keeping(&*deps.cloud, &kept_ids(&data_dir)).await;

    let (r, it) = (region.clone(), instance_type.clone());
    let apph = app.clone();
    let mut emit = move |s: ConnectState| {
        let _ = apph.emit("vpn:state", state_json(&s, &r, &it));
    };

    let conn = match core_connect(&deps, &region, &instance_type, &mut emit).await {
        Ok(c) => c,
        Err(e) => {
            // On ANY connect failure, guarantee no kill-switch rules are left behind.
            killswitch_clear_all();
            return Err(e.to_string());
        }
    };

    // Kill switch (opt-in, Windows-only): engage once the tunnel is up so a later drop can't
    // leak. It's engaged AFTER the tunnel establishes and carves out the exit node's endpoint,
    // so it never blocks the tunnel from forming. A failure here is logged and cleaned up but
    // never fails an otherwise-working connection.
    if killswitch_enabled(&data_dir) {
        if let Some(ip) = conn.instance.ipv4.as_deref() {
            if let Err(e) = killswitch_engage_for(ip) {
                eprintln!("SENTINEL: kill switch engage failed ({e}); clearing to stay fail-safe");
                killswitch_clear_all();
            }
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let started_at = now_secs();
    let active = VpnActive {
        deps: deps.clone(),
        instance_id: conn.instance.id.clone(),
        chain: vec![conn.instance.id.clone()],
        region: region.clone(),
        instance_type: instance_type.clone(),
        egress_ip: conn.instance.ipv4.clone(),
        started_at,
        stop: stop.clone(),
    };
    state.inner.lock().unwrap().vpn = Some(active);

    // Stream live throughput until disconnect.
    let wg = deps.wg.clone();
    let apph2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut prev: Option<WgCounters> = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = (now_secs() - started_at) as f64;
            if let Ok(c) = wg.counters(elapsed).await {
                let (rx, tx) = match prev {
                    Some(p) => (
                        c.rx_bytes.saturating_sub(p.rx_bytes) as f64 / 2.0,
                        c.tx_bytes.saturating_sub(p.tx_bytes) as f64 / 2.0,
                    ),
                    None => (0.0, 0.0),
                };
                prev = Some(c);
                let _ = apph2.emit(
                    "vpn:metrics",
                    json!({ "rx": rx, "tx": tx, "cpuPct": 0, "memPct": 0, "nicPct": 0, "latencyMs": 0, "ts": now_secs() * 1000 }),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    Ok(())
}

/// Max hops in a multi-hop chain (cost = N× a single node, latency compounds).
const MAX_HOPS: usize = 3;

/// A random lowercase-hex string of `bytes` bytes, via uuids (no extra dependency). Used for
/// the per-node callback token/hmac fields, which multi-hop doesn't actually call.
fn rand_hex(bytes: usize) -> String {
    let mut s = String::new();
    while s.len() < bytes * 2 {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    s.truncate(bytes * 2);
    s
}

/// Spawn the 2s throughput-emitting loop for an active tunnel (shared by single- and multi-hop).
fn spawn_metrics_loop(
    app: AppHandle,
    wg: Arc<dyn WgController>,
    stop: Arc<AtomicBool>,
    started_at: i64,
) {
    tauri::async_runtime::spawn(async move {
        let mut prev: Option<WgCounters> = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = (now_secs() - started_at) as f64;
            if let Ok(c) = wg.counters(elapsed).await {
                let (rx, tx) = match prev {
                    Some(p) => (
                        c.rx_bytes.saturating_sub(p.rx_bytes) as f64 / 2.0,
                        c.tx_bytes.saturating_sub(p.tx_bytes) as f64 / 2.0,
                    ),
                    None => (0.0, 0.0),
                };
                prev = Some(c);
                let _ = app.emit(
                    "vpn:metrics",
                    json!({ "rx": rx, "tx": tx, "cpuPct": 0, "memPct": 0, "nicPct": 0, "latencyMs": 0, "ts": now_secs() * 1000 }),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Connect through a CHAIN of exit nodes (multi-hop "bounce"). `regions` is entry→exit
/// (2..=3). Traffic enters the first hop, is forwarded hop-to-hop server-side (each hop runs a
/// wg1 client to the next), and egresses at the last. The local client keeps ONE tunnel (to the
/// entry). Experimental + real-VPN only; cost is N× a single node. All keys are app-generated so
/// no per-hop callback is needed. On ANY failure every provisioned node is destroyed (cost-safe).
#[tauri::command]
pub async fn vpn_connect_multihop(
    app: AppHandle,
    state: State<'_, AppState>,
    regions: Vec<String>,
    instance_type: Option<String>,
) -> std::result::Result<(), String> {
    let r = multihop_run(app, &state, regions, instance_type).await;
    if let Err(e) = &r {
        crate::applog::error("vpn.multihop", e);
    }
    r
}

async fn multihop_run(
    app: AppHandle,
    state: &AppState,
    regions: Vec<String>,
    instance_type: Option<String>,
) -> std::result::Result<(), String> {
    if regions.len() < 2 {
        return Err("multi-hop needs at least 2 regions".into());
    }
    if regions.len() > MAX_HOPS {
        return Err(format!("at most {MAX_HOPS} hops (cost = N× a node)"));
    }
    let itype = instance_type.unwrap_or_else(|| DEFAULT_INSTANCE_TYPE.to_string());

    if CONNECTING.swap(true, Ordering::SeqCst) {
        return Err("a connection attempt is already in progress".into());
    }
    let _connecting = ConnectingGuard;
    if state.inner.lock().unwrap().vpn.is_some() {
        return Err("already connected".into());
    }
    // Check the local WireGuard prerequisites BEFORE spending money on a Linode.
    preflight_vpn()?;
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let deps = live_deps(token);
    let data_dir = { state.inner.lock().unwrap().data_dir.clone() };
    let _ = orphan_sweep_keeping(&*deps.cloud, &kept_ids(&data_dir)).await;

    let n = regions.len();
    let entry_label = format!("{} → {}", regions[0], regions[n - 1]);
    let emit = |app: &AppHandle, s: ConnectState| {
        let _ = app.emit("vpn:state", state_json(&s, &entry_label, &itype));
    };

    // Pre-generate all keys — the app knows every hop's pubkey, so the chain is fully wired
    // without any per-hop callback. server_kps[i] = hop i's wg0; wg1_kps[i] = hop i's downstream.
    let client_kp = WgKeypair::generate();
    let server_kps: Vec<WgKeypair> = (0..n).map(|_| WgKeypair::generate()).collect();
    let wg1_kps: Vec<WgKeypair> = (0..n.saturating_sub(1))
        .map(|_| WgKeypair::generate())
        .collect();

    emit(&app, ConnectState::CreatingInstance);

    // Provision exit(n-1) → entry(0) so each hop's downstream endpoint is already known.
    let mut created: Vec<String> = Vec::new(); // exit-first
    let mut downstream: Option<(String, String)> = None; // (next hop server pubkey, ip)
    let mut entry_ip: Option<String> = None;
    let mut exit_ip: Option<String> = None;

    for i in (0..n).rev() {
        let is_exit = i == n - 1;
        let is_entry = i == 0;
        // wg0 upstream peer: the entry faces the user's client; every other hop faces the
        // previous hop's wg1.
        let (peer_pubkey, peer_ip) = if is_entry {
            (client_kp.public_base64(), "10.66.0.2".to_string())
        } else {
            (wg1_kps[i - 1].public_base64(), "10.67.0.2".to_string())
        };
        let next_hop = if is_exit {
            None
        } else {
            let (npub, nip) = downstream.clone().unwrap();
            Some(NextHop {
                wg1_privkey: wg1_kps[i].private_base64(),
                wg1_address: "10.67.0.2/32".into(),
                peer_pubkey: npub,
                peer_endpoint: format!("{nip}:51820"),
            })
        };
        let params = CloudInitParams {
            server_privkey: server_kps[i].private_base64(),
            client_pubkey: peer_pubkey,
            client_ip: peer_ip,
            listen_port: 51820,
            callback_token: rand_hex(16),
            callback_hmac_key: rand_hex(32),
            deadman_secs: 900,
            next_hop,
        };
        let ud = match render_base64(&params) {
            Ok(u) => u,
            Err(e) => {
                destroy_chain(&deps, &created).await;
                return Err(e.to_string());
            }
        };
        let spec = InstanceSpec {
            region: regions[i].clone(),
            instance_type: itype.clone(),
            user_data: ud,
            label: format!("sentinel-hop{i}"),
        };
        let inst = match deps.cloud.create(&spec).await {
            Ok(x) => x,
            Err(e) => {
                destroy_chain(&deps, &created).await;
                return Err(e.to_string());
            }
        };
        created.push(inst.id.clone());

        emit(&app, ConnectState::Booting);
        let mut running = inst.clone();
        for _ in 0..deps.max_boot_polls {
            if deps.poll_interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(deps.poll_interval_ms)).await;
            }
            if let Ok(cur) = deps.cloud.get(&inst.id).await {
                if cur.state == InstanceState::Running {
                    running = cur;
                    break;
                }
            }
        }
        if running.state != InstanceState::Running {
            destroy_chain(&deps, &created).await;
            return Err(format!("hop {i} did not boot in time"));
        }
        let ip = match running.ipv4.clone() {
            Some(ip) => ip,
            None => {
                destroy_chain(&deps, &created).await;
                return Err(format!("hop {i} reported no IP"));
            }
        };
        if is_exit {
            exit_ip = Some(ip.clone());
        }
        if is_entry {
            entry_ip = Some(ip.clone());
        }
        downstream = Some((server_kps[i].public_base64(), ip));
    }

    let entry_ip = entry_ip.unwrap();

    // Bring up the ONE local tunnel to the entry hop.
    emit(&app, ConnectState::ExchangingKeys);
    emit(&app, ConnectState::StartingTunnel);
    let conf = ClientConf {
        client_private_key: client_kp.private_base64(),
        client_address: "10.66.0.2/32".into(),
        dns: "1.1.1.1".into(),
        server_public_key: server_kps[0].public_base64(),
        server_endpoint: format!("{entry_ip}:51820"),
        allowed_ips: full_tunnel(),
        keepalive: 25,
    };
    if let Err(e) = deps.wg.up(&conf).await {
        killswitch_clear_all();
        destroy_chain(&deps, &created).await;
        return Err(e.to_string());
    }

    // Optional kill switch, engaged against the entry endpoint.
    if killswitch_enabled(&data_dir) {
        if let Err(e) = killswitch_engage_for(&entry_ip) {
            eprintln!("SENTINEL: kill switch engage failed ({e}); clearing to stay fail-safe");
            killswitch_clear_all();
        }
    }

    // chain is entry-first; `created` is exit-first.
    let mut chain = created.clone();
    chain.reverse();
    let entry_id = chain[0].clone();

    let stop = Arc::new(AtomicBool::new(false));
    let started_at = now_secs();
    spawn_metrics_loop(app.clone(), deps.wg.clone(), stop.clone(), started_at);
    let active = VpnActive {
        deps: deps.clone(),
        instance_id: entry_id.clone(),
        chain,
        region: entry_label.clone(),
        instance_type: itype.clone(),
        egress_ip: exit_ip.clone(),
        started_at,
        stop,
    };
    state.inner.lock().unwrap().vpn = Some(active);
    emit(
        &app,
        ConnectState::Connected {
            instance_id: entry_id,
            egress_ip: exit_ip,
        },
    );
    Ok(())
}

/// Destroy every node id in a (partial) chain — used to clean up on any multi-hop failure so a
/// half-built chain never leaves paid nodes running.
async fn destroy_chain(deps: &ConnectDeps, ids: &[String]) {
    for id in ids {
        let _ = deps.cloud.delete(id).await;
    }
}

#[tauri::command]
pub async fn vpn_disconnect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    // A manual disconnect: mark the time so auto-connect won't immediately re-engage, and tear
    // down the kill switch unconditionally (idempotent) so traffic is never left blocked.
    LAST_MANUAL_DISCONNECT.store(now_secs(), Ordering::Relaxed);
    killswitch_clear_all();

    let active = { state.inner.lock().unwrap().vpn.take() };
    let Some(active) = active else {
        return Ok(());
    };
    active.stop.store(true, Ordering::Relaxed);

    // Last counters for the history record (best effort).
    let last = active
        .deps
        .wg
        .counters((now_secs() - active.started_at) as f64)
        .await
        .unwrap_or_default();

    let apph = app.clone();
    let (r, it) = (active.region.clone(), active.instance_type.clone());
    let mut emit = move |s: ConnectState| {
        let _ = apph.emit("vpn:state", state_json(&s, &r, &it));
    };
    // Bring the tunnel down and destroy the ENTRY node. core_disconnect does wg.down + delete.
    let res = core_disconnect(&active.deps, &active.instance_id, &mut emit).await;
    // Destroy every other hop in the chain too (multi-hop) — never leave a paid orphan behind.
    for id in active.chain.iter().filter(|id| **id != active.instance_id) {
        let _ = active.deps.cloud.delete(id).await;
    }

    // Record the session regardless of teardown outcome.
    let ended = now_secs();
    let hourly = hourly_for(&active.instance_type);
    if let Ok(store) = history_store(&state) {
        let _ = store.insert(&SessionRecord {
            id: active.instance_id.clone(),
            region: active.region.clone(),
            instance_type: active.instance_type.clone(),
            started_at: active.started_at,
            ended_at: ended,
            bytes_rx: last.rx_bytes as i64,
            bytes_tx: last.tx_bytes as i64,
            cost_usd: CostTicker::new(hourly, active.started_at).accrued(ended),
            peak_cpu_pct: 0,
            down_mbps: 0,
            up_mbps: 0,
        });
    }
    res.map_err(|e| e.to_string())
}

fn iso(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRowOut {
    id: String,
    region: String,
    instance_type: String,
    started_at: String,
    ended_at: Option<String>,
    bytes_rx: i64,
    bytes_tx: i64,
    cost_usd: f64,
    peak_cpu_pct: i64,
    down_mbps: i64,
    up_mbps: i64,
}

#[tauri::command]
pub fn vpn_history(state: State<AppState>, range: String) -> Vec<SessionRowOut> {
    let now = now_secs();
    let from = match range.as_str() {
        "week" => now - 7 * 86400,
        "month" => now - 30 * 86400,
        _ => 0,
    };
    let Ok(store) = history_store(&state) else {
        return vec![];
    };
    store
        .list(from, now + 86400)
        .unwrap_or_default()
        .into_iter()
        .map(|s| SessionRowOut {
            id: s.id,
            region: s.region,
            instance_type: s.instance_type,
            started_at: iso(s.started_at),
            ended_at: Some(iso(s.ended_at)),
            bytes_rx: s.bytes_rx,
            bytes_tx: s.bytes_tx,
            cost_usd: s.cost_usd,
            peak_cpu_pct: s.peak_cpu_pct,
            down_mbps: s.down_mbps,
            up_mbps: s.up_mbps,
        })
        .collect()
}

/// Reap any orphaned ephemeral nodes on launch (called from setup when a token exists), keeping
/// any nodes the user deliberately kept (the registry) so a stopped/saved node survives a restart.
pub fn sweep_on_launch(data_dir: PathBuf) {
    if let Some(token) = get_token() {
        tauri::async_runtime::spawn(async move {
            let deps = live_deps(token);
            let _ = orphan_sweep_keeping(&*deps.cloud, &kept_ids(&data_dir)).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Node lifecycle (Phase 3, opt-in): keep-vs-destroy + manage multiple nodes
// ---------------------------------------------------------------------------
//
// COST MODEL: a Linode that is powered OFF still bills (you pay until it's DESTROYED). So
// "keep" saves your node/IP for a quick restart, but it does NOT stop the meter — only
// destroy/delete does. The UI surfaces a running cost across all kept nodes, and the launch +
// pre-connect orphan sweep excludes kept nodes (registry) so they aren't reaped from under you.
// One tunnel is active at a time; keeping/managing several nodes is about the fleet, not
// simultaneous tunnels (that's multi-hop, a later phase).

/// Max nodes a user can keep, so a runaway can't quietly rack up an unbounded bill.
const MAX_KEPT_NODES: usize = 5;

fn registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join("vpn-nodes.json")
}

/// The set of node ids the user deliberately kept (excluded from the orphan sweep).
fn kept_ids(data_dir: &Path) -> HashSet<String> {
    std::fs::read_to_string(registry_path(data_dir))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

fn write_kept(data_dir: &Path, ids: &HashSet<String>) {
    let list: Vec<&String> = ids.iter().collect();
    if let Ok(s) = serde_json::to_string(&list) {
        let _ = std::fs::write(registry_path(data_dir), s);
    }
}

fn kept_add(data_dir: &Path, id: &str) {
    let mut ids = kept_ids(data_dir);
    ids.insert(id.to_string());
    write_kept(data_dir, &ids);
}

fn kept_remove(data_dir: &Path, id: &str) {
    let mut ids = kept_ids(data_dir);
    ids.remove(id);
    write_kept(data_dir, &ids);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeOut {
    id: String,
    region: String,
    instance_type: String,
    /// running | booting | provisioning | stopped | deleting | gone
    state: String,
    kept: bool,
    current: bool,
    hourly_usd: f64,
}

fn state_label(s: sentinel_core::cloud::InstanceState) -> &'static str {
    use sentinel_core::cloud::InstanceState::*;
    match s {
        Provisioning => "provisioning",
        Booting => "booting",
        Running => "running",
        Stopped => "stopped",
        Deleting => "deleting",
        Gone => "gone",
    }
}

/// List every SENTINEL ephemeral node the account has, annotated with live state, whether it's
/// kept, whether it's the currently-connected node, and its hourly cost. Requires a token.
#[tauri::command]
pub async fn vpn_nodes(state: State<'_, AppState>) -> std::result::Result<Vec<NodeOut>, String> {
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let (data_dir, current) = {
        let g = state.inner.lock().unwrap();
        (
            g.data_dir.clone(),
            g.vpn.as_ref().map(|v| v.instance_id.clone()),
        )
    };
    let deps = live_deps(token);
    let kept = kept_ids(&data_dir);
    let list = deps
        .cloud
        .list_ephemeral()
        .await
        .map_err(|e| e.to_string())?;
    Ok(list
        .into_iter()
        .map(|i| NodeOut {
            hourly_usd: hourly_for(&i.instance_type),
            state: state_label(i.state).to_string(),
            kept: kept.contains(&i.id),
            current: current.as_deref() == Some(i.id.as_str()),
            id: i.id,
            region: i.region,
            instance_type: i.instance_type,
        })
        .collect())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    node_count: usize,
    running: usize,
    stopped: usize,
    hourly_usd: f64,
}

/// Running cost across ALL existing ephemeral nodes (running + stopped both bill on Linode).
#[tauri::command]
pub async fn vpn_cost_summary() -> std::result::Result<CostSummary, String> {
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let deps = live_deps(token);
    let list = deps
        .cloud
        .list_ephemeral()
        .await
        .map_err(|e| e.to_string())?;
    use sentinel_core::cloud::InstanceState;
    let mut running = 0;
    let mut stopped = 0;
    let mut hourly = 0.0;
    for i in &list {
        hourly += hourly_for(&i.instance_type);
        match i.state {
            InstanceState::Stopped => stopped += 1,
            InstanceState::Deleting | InstanceState::Gone => {}
            _ => running += 1,
        }
    }
    Ok(CostSummary {
        node_count: list.len(),
        running,
        stopped,
        hourly_usd: hourly,
    })
}

/// Tear down the local tunnel WITHOUT destroying the node: power it off and keep it (registry),
/// so it survives sweeps and can be restarted later. Note: a stopped Linode still bills.
#[tauri::command]
pub async fn vpn_disconnect_keep(
    app: AppHandle,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    LAST_MANUAL_DISCONNECT.store(now_secs(), Ordering::Relaxed);
    killswitch_clear_all();

    let (active, data_dir) = {
        let mut g = state.inner.lock().unwrap();
        (g.vpn.take(), g.data_dir.clone())
    };
    let Some(active) = active else {
        return Err("not connected".into());
    };
    if active.chain.len() > 1 {
        // Keeping a multi-hop chain would leave several nodes billing; refuse and put it back.
        state.inner.lock().unwrap().vpn = Some(active);
        return Err(
            "keep isn't supported for a multi-hop chain — use Disconnect to destroy it".into(),
        );
    }
    if kept_ids(&data_dir).len() >= MAX_KEPT_NODES {
        // Put it back so the caller can decide; refuse rather than silently destroy.
        state.inner.lock().unwrap().vpn = Some(active);
        return Err(format!(
            "already keeping {MAX_KEPT_NODES} nodes — destroy one first (each kept node keeps billing)"
        ));
    }
    active.stop.store(true, Ordering::Relaxed);

    let last = active
        .deps
        .wg
        .counters((now_secs() - active.started_at) as f64)
        .await
        .unwrap_or_default();

    // Bring the local tunnel down, then power the node off (keep it).
    let _ = active.deps.wg.down().await;
    let power = active.deps.cloud.shutdown(&active.instance_id).await;
    kept_add(&data_dir, &active.instance_id);

    let apph = app.clone();
    let _ = apph.emit(
        "vpn:state",
        state_json(&ConnectState::Idle, &active.region, &active.instance_type),
    );

    let ended = now_secs();
    let hourly = hourly_for(&active.instance_type);
    if let Ok(store) = history_store(&state) {
        let _ = store.insert(&SessionRecord {
            id: active.instance_id.clone(),
            region: active.region.clone(),
            instance_type: active.instance_type.clone(),
            started_at: active.started_at,
            ended_at: ended,
            bytes_rx: last.rx_bytes as i64,
            bytes_tx: last.tx_bytes as i64,
            cost_usd: CostTicker::new(hourly, active.started_at).accrued(ended),
            peak_cpu_pct: 0,
            down_mbps: 0,
            up_mbps: 0,
        });
    }
    power.map_err(|e| e.to_string())
}

/// Power a specific node on/off/reboot or delete it. `action` ∈ start | stop | reboot | delete.
/// If it targets the currently-connected node, the tunnel is torn down first (kill switch cleared).
#[tauri::command]
pub async fn vpn_node_action(
    state: State<'_, AppState>,
    id: String,
    action: String,
) -> std::result::Result<(), String> {
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let deps = live_deps(token);

    // If this node is the active tunnel, take it out and tear the tunnel down first (never leave a
    // dangling conf). The lock is released before any await — MutexGuard is never held across one.
    let (data_dir, teardown) = {
        let mut g = state.inner.lock().unwrap();
        let is_current = g.vpn.as_ref().map(|v| v.instance_id.as_str()) == Some(id.as_str());
        let taken = if is_current { g.vpn.take() } else { None };
        (g.data_dir.clone(), taken)
    };
    if let Some(active) = teardown {
        active.stop.store(true, Ordering::Relaxed);
        killswitch_clear_all();
        let _ = active.deps.wg.down().await;
    }

    match action.as_str() {
        "start" => deps.cloud.boot(&id).await.map_err(|e| e.to_string()),
        "reboot" => deps.cloud.reboot(&id).await.map_err(|e| e.to_string()),
        "stop" => {
            let r = deps.cloud.shutdown(&id).await.map_err(|e| e.to_string());
            if r.is_ok() {
                if kept_ids(&data_dir).len() < MAX_KEPT_NODES {
                    kept_add(&data_dir, &id);
                }
            }
            r
        }
        "delete" => {
            let r = deps.cloud.delete(&id).await.map_err(|e| e.to_string());
            kept_remove(&data_dir, &id);
            r
        }
        other => Err(format!("unknown node action: {other}")),
    }
}

/// Panic button: disconnect if connected, then DESTROY every ephemeral node and clear the
/// registry, so the billing meter stops on everything.
#[tauri::command]
pub async fn vpn_nodes_destroy_all(
    state: State<'_, AppState>,
) -> std::result::Result<usize, String> {
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    killswitch_clear_all();
    let (active, data_dir) = {
        let mut g = state.inner.lock().unwrap();
        (g.vpn.take(), g.data_dir.clone())
    };
    let deps = live_deps(token);
    if let Some(active) = active {
        active.stop.store(true, Ordering::Relaxed);
        let _ = active.deps.wg.down().await;
    }
    // Reap everything, keeping nothing.
    let reaped = orphan_sweep_keeping(&*deps.cloud, &HashSet::new())
        .await
        .map_err(|e| e.to_string())?;
    write_kept(&data_dir, &HashSet::new());
    Ok(reaped.len())
}
