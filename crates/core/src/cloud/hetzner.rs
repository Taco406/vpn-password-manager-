//! Real Hetzner Cloud API v1 client (behind `live-hetzner`). Server management only —
//! NorthKey never provisions VPN nodes on Hetzner, so this implements [`ServerManager`]
//! but not `CloudProvider`. The token comes from the OS keychain, never from source.
//!
//! Response parsing is split into pure functions so the JSON→model mapping (pagination,
//! EUR prices as strings, `[ts, "value"]` metric pairs, state names) is pinned by unit
//! tests that run in every normal `cargo test --features live-hetzner`.

#![cfg(feature = "live-hetzner")]

use super::manager::{
    MetricPoint, PowerAction, Provider, ServerEvent, ServerInfo, ServerMetrics, Snapshot,
};
use super::provider::InstanceState;
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const API: &str = "https://api.hetzner.cloud/v1";

pub struct HetznerClient {
    http: reqwest::Client,
    token: String,
}

impl HetznerClient {
    pub fn new(token: impl Into<String>) -> Self {
        HetznerClient {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
            token: token.into(),
        }
    }

    fn net(e: reqwest::Error) -> CoreError {
        CoreError::Network(e.to_string())
    }

    /// Send a request and return the raw body, surfacing Hetzner's error message on non-2xx.
    async fn body_ok(resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(hetzner_reason(status.as_u16(), &text));
        }
        Ok(text)
    }
}

/// Pull the human reason out of a Hetzner error body: `{"error":{"code":"...","message":"..."}}`.
fn hetzner_reason(status: u16, body: &str) -> CoreError {
    let reason = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let e = v.get("error")?;
            let msg = e.get("message")?.as_str()?.to_string();
            match e.get("code").and_then(|c| c.as_str()) {
                Some(code) if !code.is_empty() => Some(format!("{msg} ({code})")),
                _ => Some(msg),
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| body.trim().chars().take(300).collect());
    CoreError::Network(format!("Hetzner API {status}: {reason}"))
}

fn map_state(status: &str) -> InstanceState {
    match status {
        "running" => InstanceState::Running,
        "initializing" | "starting" => InstanceState::Booting,
        "off" => InstanceState::Stopped,
        "stopping" | "deleting" => InstanceState::Deleting,
        // migrating, rebuilding, unknown, …
        _ => InstanceState::Provisioning,
    }
}

// --- /servers DTOs ----------------------------------------------------------

#[derive(Deserialize)]
struct ServersPage {
    servers: Vec<HetznerServer>,
    #[serde(default)]
    meta: Option<Meta>,
}
#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    pagination: Option<Pagination>,
}
#[derive(Deserialize)]
struct Pagination {
    #[serde(default)]
    next_page: Option<u32>,
}

#[derive(Deserialize)]
struct HetznerServer {
    id: u64,
    name: String,
    status: String,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    public_net: Option<PublicNet>,
    server_type: ServerType,
    #[serde(default)]
    datacenter: Option<Datacenter>,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct PublicNet {
    #[serde(default)]
    ipv4: Option<IpEntry>,
    #[serde(default)]
    ipv6: Option<IpEntry>,
}
#[derive(Deserialize)]
struct IpEntry {
    #[serde(default)]
    ip: Option<String>,
}
#[derive(Deserialize)]
struct ServerType {
    name: String,
    #[serde(default)]
    cores: u32,
    /// GB, fractional for shared types (e.g. 4.0).
    #[serde(default)]
    memory: f64,
    /// GB.
    #[serde(default)]
    disk: u32,
    #[serde(default)]
    prices: Vec<PriceEntry>,
}
#[derive(Deserialize)]
struct PriceEntry {
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    price_hourly: Option<Price>,
    #[serde(default)]
    price_monthly: Option<Price>,
}
#[derive(Deserialize)]
struct Price {
    /// Hetzner sends prices as decimal STRINGS (e.g. "0.0063000000").
    #[serde(default)]
    gross: String,
}

fn price_f64(p: &Option<Price>) -> f64 {
    p.as_ref()
        .and_then(|p| p.gross.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn server_info(s: HetznerServer) -> ServerInfo {
    let location = s
        .datacenter
        .as_ref()
        .and_then(|d| d.location.as_ref())
        .map(|l| l.name.clone())
        .unwrap_or_default();
    // Prices are per-location; match the server's location, else take the first entry.
    let price = s
        .server_type
        .prices
        .iter()
        .find(|p| p.location.as_deref() == Some(location.as_str()))
        .or_else(|| s.server_type.prices.first());
    let (hourly, monthly) = price
        .map(|p| (price_f64(&p.price_hourly), price_f64(&p.price_monthly)))
        .unwrap_or((0.0, 0.0));
    let created_at = s
        .created
        .as_deref()
        .and_then(|c| OffsetDateTime::parse(c, &Rfc3339).ok())
        .map(|t| t.unix_timestamp());
    ServerInfo {
        provider: Provider::Hetzner,
        id: s.id.to_string(),
        label: s.name,
        region: location,
        instance_type: s.server_type.name.clone(),
        state: map_state(&s.status),
        ipv4: s
            .public_net
            .as_ref()
            .and_then(|n| n.ipv4.as_ref())
            .and_then(|e| e.ip.clone()),
        ipv6: s
            .public_net
            .as_ref()
            .and_then(|n| n.ipv6.as_ref())
            .and_then(|e| e.ip.clone()),
        tags: s
            .labels
            .into_iter()
            .map(|(k, v)| if v.is_empty() { k } else { format!("{k}={v}") })
            .collect(),
        created_at,
        vcpus: s.server_type.cores,
        memory_mb: (s.server_type.memory * 1024.0).round() as u32,
        disk_gb: s.server_type.disk,
        hourly,
        monthly,
        currency: "EUR",
    }
}

#[derive(Deserialize)]
struct Datacenter {
    #[serde(default)]
    location: Option<Location>,
}
#[derive(Deserialize)]
struct Location {
    name: String,
}

/// Parse one /servers page body → (servers, next_page).
fn parse_servers_page(body: &str) -> Result<(Vec<ServerInfo>, Option<u32>)> {
    let page: ServersPage = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Hetzner API: bad response ({e})")))?;
    let next = page
        .meta
        .and_then(|m| m.pagination)
        .and_then(|p| p.next_page);
    Ok((page.servers.into_iter().map(server_info).collect(), next))
}

// --- /servers/{id}/metrics --------------------------------------------------

/// Parse a metrics body. `time_series` values arrive as `[ts, "value-as-string"]` pairs.
fn parse_metrics(body: &str) -> Result<ServerMetrics> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Hetzner API: bad response ({e})")))?;
    let ts_map = v
        .get("metrics")
        .and_then(|m| m.get("time_series"))
        .cloned()
        .unwrap_or_default();

    let series = |key: &str| -> Vec<MetricPoint> {
        ts_map
            .get(key)
            .and_then(|s| s.get("values"))
            .and_then(|vals| vals.as_array())
            .map(|vals| {
                vals.iter()
                    .filter_map(|pair| {
                        let ts = pair.get(0)?.as_f64()? as i64;
                        let raw = pair.get(1)?;
                        let value = raw
                            .as_str()
                            .and_then(|s| s.parse::<f64>().ok())
                            .or_else(|| raw.as_f64())?;
                        Some(MetricPoint { ts, value })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    // Disk IO: read + write IOPS summed per sample (same query ⇒ aligned timestamps).
    let (reads, writes) = (series("disk.0.iops.read"), series("disk.0.iops.write"));
    let disk_io = if writes.is_empty() {
        reads.clone()
    } else {
        reads
            .iter()
            .zip(writes.iter())
            .map(|(r, w)| MetricPoint {
                ts: r.ts,
                value: r.value + w.value,
            })
            .collect()
    };

    Ok(ServerMetrics {
        cpu_pct: series("cpu"),
        net_in_bps: series("network.0.bandwidth.in"),
        net_out_bps: series("network.0.bandwidth.out"),
        disk_io,
    })
}

// --- /images (snapshots) ----------------------------------------------------

#[derive(Deserialize)]
struct ImagesPage {
    #[serde(default)]
    images: Vec<HetznerImage>,
}
#[derive(Deserialize)]
struct HetznerImage {
    id: u64,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    image_size: Option<f64>,
    #[serde(default)]
    status: Option<String>,
}

/// Parse a `/images?type=snapshot&bound_to={id}` body → snapshots, newest first.
fn parse_images(body: &str) -> Result<Vec<Snapshot>> {
    let page: ImagesPage = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Hetzner API: bad response ({e})")))?;
    let mut out: Vec<Snapshot> = page
        .images
        .into_iter()
        .map(|i| Snapshot {
            id: i.id.to_string(),
            label: i.description.unwrap_or_else(|| format!("image {}", i.id)),
            created_at: i
                .created
                .as_deref()
                .and_then(|c| OffsetDateTime::parse(c, &Rfc3339).ok())
                .map(|t| t.unix_timestamp()),
            size_gb: i.image_size,
            status: i.status.unwrap_or_default(),
        })
        .collect();
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

// --- /servers/{id}/actions (activity feed) ----------------------------------

#[derive(Deserialize)]
struct ActionsPage {
    #[serde(default)]
    actions: Vec<HetznerAction>,
}
#[derive(Deserialize)]
struct HetznerAction {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    progress: Option<f64>,
    #[serde(default)]
    started: Option<String>,
    #[serde(default)]
    finished: Option<String>,
}

/// Parse a `/servers/{id}/actions` body → events, newest first.
fn parse_actions(body: &str) -> Result<Vec<ServerEvent>> {
    let page: ActionsPage = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Hetzner API: bad response ({e})")))?;
    let mut out: Vec<ServerEvent> = page
        .actions
        .into_iter()
        .map(|a| ServerEvent {
            action: a.command.unwrap_or_else(|| "action".into()),
            status: a.status.unwrap_or_default(),
            // Prefer finished time, else started.
            created_at: a
                .finished
                .as_deref()
                .or(a.started.as_deref())
                .and_then(|c| OffsetDateTime::parse(c, &Rfc3339).ok())
                .map(|t| t.unix_timestamp()),
            progress: a.progress,
        })
        .collect();
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

// --- /firewalls -------------------------------------------------------------

/// One firewall rule, in Hetzner's exact wire shape so a read→modify→write round-trip is
/// lossless. Empty vectors are dropped on write (Hetzner rejects `destination_ips` on an `in`
/// rule and vice-versa), and `port`/`description` are omitted when absent.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct FirewallRule {
    pub direction: String, // "in" | "out"
    pub protocol: String,  // "tcp" | "udp" | "icmp" | "esp" | "gre"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>, // "19999", "80-85", or None (icmp/esp/gre)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A Hetzner Cloud Firewall with the servers it's applied to and its current rule set.
#[derive(Clone, Debug)]
pub struct Firewall {
    pub id: u64,
    pub name: String,
    pub rules: Vec<FirewallRule>,
    pub applied_server_ids: Vec<u64>,
}

#[derive(Deserialize)]
struct FirewallsPage {
    #[serde(default)]
    firewalls: Vec<HetznerFirewall>,
}
#[derive(Deserialize)]
struct HetznerFirewall {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    rules: Vec<FirewallRule>,
    #[serde(default)]
    applied_to: Vec<AppliedTo>,
}
#[derive(Deserialize)]
struct AppliedTo {
    #[serde(default)]
    server: Option<AppliedServer>,
}
#[derive(Deserialize)]
struct AppliedServer {
    id: u64,
}

/// Parse a `/firewalls` body → firewalls with their applied-server ids.
fn parse_firewalls(body: &str) -> Result<Vec<Firewall>> {
    let page: FirewallsPage = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Hetzner API: bad response ({e})")))?;
    Ok(page
        .firewalls
        .into_iter()
        .map(|f| Firewall {
            id: f.id,
            name: f.name,
            rules: f.rules,
            applied_server_ids: f
                .applied_to
                .into_iter()
                .filter_map(|a| a.server.map(|s| s.id))
                .collect(),
        })
        .collect())
}

impl HetznerClient {
    /// List every firewall on the account (with its rules + applied servers).
    pub async fn list_firewalls(&self) -> Result<Vec<Firewall>> {
        let resp = self
            .http
            .get(format!("{API}/firewalls?per_page=50"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let body = Self::body_ok(resp).await?;
        parse_firewalls(&body)
    }

    /// Replace a firewall's ENTIRE rule set (Hetzner has no add-one-rule endpoint). Callers
    /// must read the current rules, append, and pass the full list — never a partial set.
    pub async fn set_firewall_rules(&self, firewall_id: u64, rules: &[FirewallRule]) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/firewalls/{firewall_id}/actions/set_rules"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "rules": rules }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::body_ok(resp).await.map(|_| ())
    }

    /// Create a firewall with `rules` and apply it to `server_id`. Returns the new firewall id.
    /// Used when a server has no firewall yet and the user asks to open a port.
    pub async fn create_firewall(
        &self,
        name: &str,
        rules: &[FirewallRule],
        server_id: u64,
    ) -> Result<u64> {
        let resp = self
            .http
            .post(format!("{API}/firewalls"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "name": name,
                "rules": rules,
                "apply_to": [{ "type": "server", "server": { "id": server_id } }],
            }))
            .send()
            .await
            .map_err(Self::net)?;
        let body = Self::body_ok(resp).await?;
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("firewall")?.get("id")?.as_u64())
            .ok_or_else(|| CoreError::Network("Hetzner API: firewall create returned no id".into()))
    }
}

// --- the client -------------------------------------------------------------

#[async_trait]
impl super::manager::ServerManager for HetznerClient {
    async fn list_all(&self) -> Result<Vec<ServerInfo>> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let resp = self
                .http
                .get(format!("{API}/servers?page={page}&per_page=50"))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(Self::net)?;
            let body = Self::body_ok(resp).await?;
            let (mut servers, next) = parse_servers_page(&body)?;
            out.append(&mut servers);
            match next {
                Some(n) if n != page => page = n,
                _ => break,
            }
        }
        Ok(out)
    }

    async fn metrics(&self, id: &str, window_secs: u32) -> Result<ServerMetrics> {
        let now = OffsetDateTime::now_utc();
        let start = now - time::Duration::seconds(window_secs.max(60) as i64);
        let step = (window_secs / 90).max(1);
        let (start_s, end_s) = (
            start.format(&Rfc3339).unwrap_or_default(),
            now.format(&Rfc3339).unwrap_or_default(),
        );
        let resp = self
            .http
            .get(format!(
                "{API}/servers/{id}/metrics?type=cpu,network,disk&start={start_s}&end={end_s}&step={step}"
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let body = Self::body_ok(resp).await?;
        parse_metrics(&body)
    }

    async fn power(&self, id: &str, action: PowerAction) -> Result<()> {
        // Graceful `shutdown` (ACPI), not the hard `poweroff`.
        let path = match action {
            PowerAction::Boot => "poweron",
            PowerAction::Shutdown => "shutdown",
            PowerAction::Reboot => "reboot",
        };
        let resp = self
            .http
            .post(format!("{API}/servers/{id}/actions/{path}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        Self::body_ok(resp).await.map(|_| ())
    }

    async fn snapshot(&self, id: &str, label: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/servers/{id}/actions/create_image"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "type": "snapshot", "description": label }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::body_ok(resp).await.map(|_| ())
    }

    async fn list_snapshots(&self, id: &str) -> Result<Vec<Snapshot>> {
        let resp = self
            .http
            .get(format!("{API}/images?type=snapshot&bound_to={id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let body = Self::body_ok(resp).await?;
        parse_images(&body)
    }

    async fn set_rdns(&self, id: &str, ip: &str, ptr: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/servers/{id}/actions/change_dns_ptr"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "ip": ip, "dns_ptr": ptr }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::body_ok(resp).await.map(|_| ())
    }

    async fn set_protection(&self, id: &str, on: bool) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/servers/{id}/actions/change_protection"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "delete": on, "rebuild": on }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::body_ok(resp).await.map(|_| ())
    }

    async fn recent_events(&self, id: &str) -> Result<Vec<ServerEvent>> {
        let resp = self
            .http
            .get(format!(
                "{API}/servers/{id}/actions?per_page=15&sort=started:desc"
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let body = Self::body_ok(resp).await?;
        parse_actions(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE1: &str = r#"{
      "servers": [{
        "id": 42, "name": "web-1", "status": "running",
        "created": "2024-03-01T10:00:00+00:00",
        "public_net": {"ipv4": {"ip": "1.2.3.4"}, "ipv6": {"ip": "2001:db8::1"}},
        "server_type": {
          "name": "cx22", "cores": 2, "memory": 4.0, "disk": 40,
          "prices": [
            {"location": "fsn1", "price_hourly": {"gross": "0.0074000000"}, "price_monthly": {"gross": "4.5900000000"}},
            {"location": "nbg1", "price_hourly": {"gross": "0.0080000000"}, "price_monthly": {"gross": "4.9900000000"}}
          ]
        },
        "datacenter": {"location": {"name": "nbg1"}},
        "labels": {"env": "prod", "netdata": ""}
      }],
      "meta": {"pagination": {"next_page": 2}}
    }"#;

    const PAGE2: &str = r#"{
      "servers": [{
        "id": 43, "name": "db-1", "status": "off",
        "server_type": {"name": "cx32", "cores": 4, "memory": 8.0, "disk": 80, "prices": []},
        "datacenter": {"location": {"name": "fsn1"}},
        "labels": {}
      }],
      "meta": {"pagination": {"next_page": null}}
    }"#;

    #[test]
    fn parses_paginated_servers_with_location_priced_eur() {
        let (s1, next1) = parse_servers_page(PAGE1).unwrap();
        assert_eq!(next1, Some(2));
        assert_eq!(s1.len(), 1);
        let s = &s1[0];
        assert_eq!(s.id, "42");
        assert_eq!(s.provider, Provider::Hetzner);
        assert_eq!(s.state, InstanceState::Running);
        assert_eq!(s.ipv4.as_deref(), Some("1.2.3.4"));
        assert_eq!(s.region, "nbg1");
        // Matched the nbg1 price entry, not fsn1.
        assert!((s.hourly - 0.008).abs() < 1e-9);
        assert!((s.monthly - 4.99).abs() < 1e-9);
        assert_eq!(s.currency, "EUR");
        assert_eq!(s.memory_mb, 4096);
        assert_eq!(s.tags, vec!["env=prod".to_string(), "netdata".to_string()]);
        assert!(s.created_at.is_some());

        let (s2, next2) = parse_servers_page(PAGE2).unwrap();
        assert_eq!(next2, None);
        assert_eq!(s2[0].state, InstanceState::Stopped);
        assert_eq!(s2[0].hourly, 0.0);
    }

    #[test]
    fn parses_metrics_string_values_and_sums_disk() {
        let body = r#"{"metrics": {"start": "x", "end": "y", "step": 60, "time_series": {
            "cpu": {"values": [[1700000000, "12.5"], [1700000060, "14.0"]]},
            "network.0.bandwidth.in": {"values": [[1700000000, "1024"]]},
            "network.0.bandwidth.out": {"values": [[1700000000, "2048.5"]]},
            "disk.0.iops.read": {"values": [[1700000000, "3"]]},
            "disk.0.iops.write": {"values": [[1700000000, "7"]]}
        }}}"#;
        let m = parse_metrics(body).unwrap();
        assert_eq!(m.cpu_pct.len(), 2);
        assert!((m.cpu_pct[1].value - 14.0).abs() < 1e-9);
        assert_eq!(m.cpu_pct[0].ts, 1700000000);
        assert!((m.net_in_bps[0].value - 1024.0).abs() < 1e-9);
        assert!((m.net_out_bps[0].value - 2048.5).abs() < 1e-9);
        assert!((m.disk_io[0].value - 10.0).abs() < 1e-9);
    }

    #[test]
    fn error_body_surfaces_message_and_code() {
        let e = hetzner_reason(
            423,
            r#"{"error":{"code":"locked","message":"server is locked"}}"#,
        );
        let msg = format!("{e}");
        assert!(msg.contains("server is locked"), "{msg}");
        assert!(msg.contains("locked"), "{msg}");
        assert!(msg.contains("423"), "{msg}");
    }

    #[test]
    fn state_mapping() {
        assert_eq!(map_state("running"), InstanceState::Running);
        assert_eq!(map_state("initializing"), InstanceState::Booting);
        assert_eq!(map_state("starting"), InstanceState::Booting);
        assert_eq!(map_state("off"), InstanceState::Stopped);
        assert_eq!(map_state("stopping"), InstanceState::Deleting);
        assert_eq!(map_state("migrating"), InstanceState::Provisioning);
    }

    #[test]
    fn parses_snapshot_images_newest_first() {
        let body = r#"{"images": [
            {"id": 100, "description": "before-upgrade", "created": "2024-05-01T10:00:00+00:00", "image_size": 2.5, "status": "available"},
            {"id": 101, "description": "nightly", "created": "2024-06-01T10:00:00+00:00", "image_size": 3.0, "status": "creating"}
        ]}"#;
        let snaps = parse_images(body).unwrap();
        assert_eq!(snaps.len(), 2);
        // Newest (June) sorts first.
        assert_eq!(snaps[0].label, "nightly");
        assert_eq!(snaps[0].id, "101");
        assert_eq!(snaps[0].status, "creating");
        assert!((snaps[0].size_gb.unwrap() - 3.0).abs() < 1e-9);
        assert_eq!(snaps[1].label, "before-upgrade");
        assert!(snaps[1].created_at.unwrap() < snaps[0].created_at.unwrap());
    }

    #[test]
    fn parses_firewalls_with_rules_and_applied_servers() {
        let body = r#"{"firewalls": [{
            "id": 77, "name": "coolify",
            "rules": [
                {"direction":"in","protocol":"tcp","port":"22","source_ips":["0.0.0.0/0","::/0"],"destination_ips":[],"description":"ssh"},
                {"direction":"in","protocol":"tcp","port":"443","source_ips":["0.0.0.0/0"]}
            ],
            "applied_to": [{"type":"server","server":{"id":42}}]
        }]}"#;
        let fws = parse_firewalls(body).unwrap();
        assert_eq!(fws.len(), 1);
        let f = &fws[0];
        assert_eq!(f.id, 77);
        assert_eq!(f.applied_server_ids, vec![42]);
        assert_eq!(f.rules.len(), 2);
        assert_eq!(f.rules[0].port.as_deref(), Some("22"));
        // Round-trips: an `in` rule serializes without the empty destination_ips.
        let json = serde_json::to_string(&f.rules[0]).unwrap();
        assert!(json.contains("\"source_ips\""), "{json}");
        assert!(!json.contains("destination_ips"), "{json}");
    }

    #[test]
    fn parses_actions_feed_prefers_finished_time() {
        let body = r#"{"actions": [
            {"command": "create_image", "status": "success", "progress": 100,
             "started": "2024-06-01T10:00:00+00:00", "finished": "2024-06-01T10:05:00+00:00"},
            {"command": "reboot", "status": "running", "progress": 40,
             "started": "2024-06-02T09:00:00+00:00", "finished": null}
        ]}"#;
        let evs = parse_actions(body).unwrap();
        assert_eq!(evs.len(), 2);
        // The running reboot (started later) sorts newest-first over the finished create_image.
        assert_eq!(evs[0].action, "reboot");
        assert_eq!(evs[0].status, "running");
        assert!((evs[0].progress.unwrap() - 40.0).abs() < 1e-9);
        assert_eq!(evs[1].action, "create_image");
        // create_image uses its finished timestamp (10:05), not started (10:00).
        let finished = OffsetDateTime::parse("2024-06-01T10:05:00+00:00", &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(evs[1].created_at, Some(finished));
    }
}
