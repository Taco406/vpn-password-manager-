//! The Servers screen backend: one unified view over every server the user owns —
//! all Linode instances (including NorthKey's own tagged nodes, labeled by role) and
//! all Hetzner Cloud servers — with power actions and real utilization metrics.
//!
//! Deliberately separate from `vpn.rs`'s tag-scoped node management: nothing here is
//! ever fed to the ephemeral orphan sweep, and powering the node that carries the
//! active VPN tunnel is refused (that teardown path lives on the VPN screen).

use sentinel_core::cloud::{HetznerClient, LinodeClient, PowerAction, ServerInfo, ServerManager};
use serde::Serialize;
use tauri::State;

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
