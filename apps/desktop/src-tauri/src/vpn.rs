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
use sentinel_core::cloud::LinodeClient;
use sentinel_core::error::{CoreError, Result as CoreResult};
use sentinel_core::provision::{verify_callback, CallbackBody};
use sentinel_core::vpn::{
    connect as core_connect, disconnect as core_disconnect, orphan_sweep, ConnectDeps,
    ConnectState, ServerPubkeyFetcher,
};
use sentinel_core::vpn::{CostTicker, HistoryStore, SessionRecord};
use sentinel_core::wg::{render_client_conf, ClientConf, WgController, WgCounters};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

const KC_SERVICE: &str = "com.sentinel.desktop";
const KC_LINODE: &str = "linode-token";
const TUNNEL: &str = "sentinel";

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
}

// Linode region ids (valid for `create`) with coordinates for the globe.
const REGIONS: &[RegionRow] = &[
    RegionRow {
        id: "us-east",
        label: "Newark, NJ",
        country: "US",
        lat: 40.74,
        lon: -74.17,
    },
    RegionRow {
        id: "us-central",
        label: "Dallas, TX",
        country: "US",
        lat: 32.78,
        lon: -96.80,
    },
    RegionRow {
        id: "us-west",
        label: "Fremont, CA",
        country: "US",
        lat: 37.55,
        lon: -121.98,
    },
    RegionRow {
        id: "us-southeast",
        label: "Atlanta, GA",
        country: "US",
        lat: 33.75,
        lon: -84.39,
    },
    RegionRow {
        id: "ca-central",
        label: "Toronto",
        country: "CA",
        lat: 43.65,
        lon: -79.38,
    },
    RegionRow {
        id: "eu-west",
        label: "London",
        country: "GB",
        lat: 51.51,
        lon: -0.13,
    },
    RegionRow {
        id: "eu-central",
        label: "Frankfurt",
        country: "DE",
        lat: 50.11,
        lon: 8.68,
    },
    RegionRow {
        id: "ap-south",
        label: "Singapore",
        country: "SG",
        lat: 1.35,
        lon: 103.82,
    },
    RegionRow {
        id: "ap-northeast",
        label: "Tokyo",
        country: "JP",
        lat: 35.68,
        lon: 139.69,
    },
    RegionRow {
        id: "ap-southeast",
        label: "Sydney",
        country: "AU",
        lat: -33.87,
        lon: 151.21,
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
            run(&wireguard_bin(), &["/installtunnelservice", &path]).await?;
        } else {
            run("wg-quick", &["up", &path]).await?;
        }

        // Consider the tunnel "up" only once a real handshake lands (so "Connected" never
        // lies). Poll ~60s; on timeout return Err so the FSM tears the instance down.
        for _ in 0..30 {
            if self.latest_handshake().await > 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(wg_err("no WireGuard handshake within 60s"))
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
                .timeout(Duration::from_secs(8))
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
        // The node may still be booting its responder — retry with backoff (~60s).
        for _ in 0..30 {
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
    pub instance_id: String,
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
        max_boot_polls: 60,
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

#[tauri::command]
pub fn vpn_regions_real() -> Vec<RegionOut> {
    REGIONS
        .iter()
        .map(|r| RegionOut {
            id: r.id.into(),
            label: r.label.into(),
            country: r.country.into(),
            lat: r.lat,
            lon: r.lon,
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

#[tauri::command]
pub async fn vpn_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    region: String,
    instance_type: String,
) -> std::result::Result<(), String> {
    if state.inner.lock().unwrap().vpn.is_some() {
        return Err("already connected".into());
    }
    let token = get_token().ok_or_else(|| "no Linode token configured".to_string())?;
    let deps = live_deps(token);

    // Reap any orphaned nodes before creating a new one.
    let _ = orphan_sweep(&*deps.cloud, None).await;

    let (r, it) = (region.clone(), instance_type.clone());
    let apph = app.clone();
    let mut emit = move |s: ConnectState| {
        let _ = apph.emit("vpn:state", state_json(&s, &r, &it));
    };

    let conn = core_connect(&deps, &region, &instance_type, &mut emit)
        .await
        .map_err(|e| e.to_string())?;

    let stop = Arc::new(AtomicBool::new(false));
    let started_at = now_secs();
    let active = VpnActive {
        deps: deps.clone(),
        instance_id: conn.instance.id.clone(),
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

#[tauri::command]
pub async fn vpn_disconnect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
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
    let res = core_disconnect(&active.deps, &active.instance_id, &mut emit).await;

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

/// Reap any orphaned ephemeral nodes on launch (called from setup when a token exists).
pub fn sweep_on_launch() {
    if let Some(token) = get_token() {
        tauri::async_runtime::spawn(async move {
            let deps = live_deps(token);
            let _ = orphan_sweep(&*deps.cloud, None).await;
        });
    }
}
