//! Real Linode API v4 client (behind `live-linode`). Never compiled into normal test
//! builds; the token comes from the OS keychain, never from source.

#![cfg(feature = "live-linode")]

use super::provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Deserialize;

const API: &str = "https://api.linode.com/v4";

pub struct LinodeClient {
    http: reqwest::Client,
    token: String,
    root_pass: String,
}

impl LinodeClient {
    pub fn new(token: impl Into<String>) -> Self {
        LinodeClient {
            http: reqwest::Client::new(),
            token: token.into(),
            // A random unused root password; SSH is disabled by cloud-init anyway.
            root_pass: {
                use rand::RngCore;
                let mut b = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut b);
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
            },
        }
    }

    fn net(e: reqwest::Error) -> CoreError {
        CoreError::Network(e.to_string())
    }

    /// Read a Linode error response body and pull out its human reason. Linode returns
    /// `{"errors":[{"reason":"...","field":"..."}]}`; surfacing that (instead of a bare HTTP
    /// status) is what tells the user *why* a create failed — bad token scope, an un-activated
    /// account, an unsupported region, etc.
    fn linode_reason(status: reqwest::StatusCode, body: &str) -> CoreError {
        let reason = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("errors")
                    .and_then(|e| e.get(0))
                    .map(|e0| {
                        let r = e0.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                        match e0.get("field").and_then(|f| f.as_str()) {
                            Some(f) if !f.is_empty() => format!("{r} ({f})"),
                            _ => r.to_string(),
                        }
                    })
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| body.trim().chars().take(300).collect());
        CoreError::Network(format!("Linode API {}: {reason}", status.as_u16()))
    }

    /// Send a request and decode JSON, surfacing Linode's error reason on non-2xx.
    async fn json_ok<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(Self::linode_reason(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))
    }

    /// Send a request expecting an empty 2xx, surfacing Linode's error reason on non-2xx.
    async fn empty_ok(resp: reqwest::Response) -> Result<()> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        Err(Self::linode_reason(status, &text))
    }
}

fn map_state(status: &str) -> InstanceState {
    match status {
        "provisioning" | "migrating" | "rebuilding" => InstanceState::Provisioning,
        "booting" | "rebooting" => InstanceState::Booting,
        "running" => InstanceState::Running,
        "offline" | "stopped" => InstanceState::Stopped,
        "shutting_down" | "deleting" => InstanceState::Deleting,
        _ => InstanceState::Provisioning,
    }
}

#[derive(Deserialize)]
struct LinodeInstance {
    id: u64,
    region: String,
    #[serde(rename = "type")]
    kind: String,
    status: String,
    ipv4: Vec<String>,
    tags: Vec<String>,
    // Extras used only by the full-account server manager (`list_all`). Optional so the
    // narrow ephemeral-sweep deserialization path is completely unaffected.
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    ipv6: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    specs: Option<LinodeSpecs>,
}

#[derive(Deserialize)]
struct LinodeSpecs {
    #[serde(default)]
    vcpus: u32,
    /// MB.
    #[serde(default)]
    memory: u32,
    /// MB (Linode reports disk in MB).
    #[serde(default)]
    disk: u32,
}

impl From<LinodeInstance> for Instance {
    fn from(l: LinodeInstance) -> Self {
        Instance {
            id: l.id.to_string(),
            region: l.region,
            instance_type: l.kind,
            state: map_state(&l.status),
            ipv4: l.ipv4.into_iter().next(),
            tags: l.tags,
        }
    }
}

use base64::Engine as _;

#[async_trait]
impl CloudProvider for LinodeClient {
    async fn create(&self, spec: &InstanceSpec) -> Result<Instance> {
        // Empty tags = ephemeral (managed by the orphan sweep); a durable node passes its own.
        let tags: Vec<String> = if spec.tags.is_empty() {
            vec![EPHEMERAL_TAG.to_string()]
        } else {
            spec.tags.clone()
        };
        let body = serde_json::json!({
            "region": spec.region,
            "type": spec.instance_type,
            "label": spec.label,
            "image": "linode/debian12",
            "root_pass": self.root_pass,
            "tags": tags,
            "backups_enabled": false,
            "private_ip": false,
            "metadata": { "user_data": spec.user_data },
        });
        let resp = self
            .http
            .post(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(Self::net)?;
        let inst: LinodeInstance = Self::json_ok(resp).await?;
        Ok(inst.into())
    }

    async fn get(&self, id: &str) -> Result<Instance> {
        let resp = self
            .http
            .get(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let inst: LinodeInstance = Self::json_ok(resp).await?;
        Ok(inst.into())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }

    async fn list_ephemeral(&self) -> Result<Vec<Instance>> {
        #[derive(Deserialize)]
        struct Page {
            data: Vec<LinodeInstance>,
        }
        let filter = serde_json::json!({ "tags": EPHEMERAL_TAG }).to_string();
        let resp = self
            .http
            .get(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .header("X-Filter", filter)
            .send()
            .await
            .map_err(Self::net)?;
        let page: Page = Self::json_ok(resp).await?;
        Ok(page.data.into_iter().map(Instance::from).collect())
    }

    async fn regions(&self) -> Result<Vec<Region>> {
        #[derive(Deserialize)]
        struct Page {
            data: Vec<RegionRow>,
        }
        #[derive(Deserialize)]
        struct RegionRow {
            id: String,
            label: String,
            country: String,
        }
        let resp = self
            .http
            .get(format!("{API}/regions"))
            .send()
            .await
            .map_err(Self::net)?;
        let page: Page = Self::json_ok(resp).await?;
        Ok(page
            .data
            .into_iter()
            .map(|r| Region {
                id: r.id,
                label: r.label,
                country: r.country,
            })
            .collect())
    }

    fn price_per_hour(&self, instance_type: &str) -> f64 {
        match instance_type {
            "g6-nanode-1" => 0.0075,
            "g6-standard-2" => 0.036,
            "g6-standard-4" => 0.072,
            "g6-dedicated-4" => 0.108,
            _ => 0.0075,
        }
    }

    async fn shutdown(&self, id: &str) -> Result<()> {
        self.power(id, "shutdown").await
    }

    async fn boot(&self, id: &str) -> Result<()> {
        self.power(id, "boot").await
    }

    async fn reboot(&self, id: &str) -> Result<()> {
        self.power(id, "reboot").await
    }
}

impl LinodeClient {
    /// POST a power action (`boot`/`shutdown`/`reboot`) to a Linode instance.
    async fn power(&self, id: &str, action: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/linode/instances/{id}/{action}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }
}

// ---------------------------------------------------------------------------
// Full-account server management (the Servers screen). Separate from the tag-scoped
// CloudProvider view — nothing here is ever fed to the ephemeral orphan sweep.
// ---------------------------------------------------------------------------

use super::manager::{
    MetricPoint, PowerAction, Provider, ServerEvent, ServerInfo, ServerManager, ServerMetrics,
    Snapshot,
};

/// Parse a Linode datetime ("YYYY-MM-DDTHH:MM:SS", UTC, no offset) → unix seconds.
fn linode_time(c: &str) -> Option<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(c, &fmt)
        .ok()
        .map(|t| t.assume_utc().unix_timestamp())
}

/// Known monthly caps (Linode bills hourly up to a fixed monthly price).
fn linode_monthly(instance_type: &str, hourly: f64) -> f64 {
    match instance_type {
        "g6-nanode-1" => 5.0,
        "g6-standard-2" => 24.0,
        "g6-standard-4" => 48.0,
        "g6-dedicated-4" => 72.0,
        _ => hourly * 730.0,
    }
}

fn server_info(l: LinodeInstance, hourly: f64) -> ServerInfo {
    let created_at = l.created.as_deref().and_then(linode_time);
    let specs = l.specs.as_ref();
    ServerInfo {
        provider: Provider::Linode,
        id: l.id.to_string(),
        label: l.label.clone().unwrap_or_else(|| l.id.to_string()),
        region: l.region.clone(),
        instance_type: l.kind.clone(),
        state: map_state(&l.status),
        ipv4: l.ipv4.first().cloned(),
        ipv6: l.ipv6.clone(),
        tags: l.tags.clone(),
        created_at,
        vcpus: specs.map(|s| s.vcpus).unwrap_or(0),
        memory_mb: specs.map(|s| s.memory).unwrap_or(0),
        disk_gb: specs.map(|s| s.disk / 1024).unwrap_or(0),
        monthly: linode_monthly(&l.kind, hourly),
        hourly,
        currency: "USD",
    }
}

/// Parse one /linode/instances page body → (rows, total pages).
fn parse_instances_page(body: &str, price: impl Fn(&str) -> f64) -> Result<(Vec<ServerInfo>, u32)> {
    #[derive(Deserialize)]
    struct Page {
        data: Vec<LinodeInstance>,
        #[serde(default)]
        pages: u32,
    }
    let page: Page = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))?;
    let pages = page.pages.max(1);
    Ok((
        page.data
            .into_iter()
            .map(|l| {
                let hourly = price(&l.kind);
                server_info(l, hourly)
            })
            .collect(),
        pages,
    ))
}

/// Parse a /linode/instances/{id}/stats body. Timestamps arrive in MILLISECONDS and
/// `netv4` series are BITS/second — both normalized here (seconds, bytes/s).
fn parse_stats(body: &str) -> Result<ServerMetrics> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))?;
    let data = v.get("data").cloned().unwrap_or_default();

    let series = |val: Option<&serde_json::Value>, scale: f64| -> Vec<MetricPoint> {
        val.and_then(|s| s.as_array())
            .map(|pairs| {
                pairs
                    .iter()
                    .filter_map(|p| {
                        let ts_ms = p.get(0)?.as_f64()?;
                        let value = p.get(1)?.as_f64()? * scale;
                        Some(MetricPoint {
                            ts: (ts_ms / 1000.0) as i64,
                            value,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(ServerMetrics {
        cpu_pct: series(data.get("cpu"), 1.0),
        // bits/s → bytes/s
        net_in_bps: series(data.get("netv4").and_then(|n| n.get("in")), 1.0 / 8.0),
        net_out_bps: series(data.get("netv4").and_then(|n| n.get("out")), 1.0 / 8.0),
        disk_io: series(data.get("io").and_then(|i| i.get("io")), 1.0),
    })
}

// --- Stage 3 parsers (snapshots via backups, activity via account events) ---

/// Parse a `/linode/instances/{id}/backups` body → the manual-snapshot slot (in-progress first,
/// then the current completed snapshot). Automatic daily backups are intentionally excluded.
fn parse_linode_backups(body: &str) -> Result<Vec<Snapshot>> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        snapshot: Option<Slot>,
    }
    #[derive(Deserialize)]
    struct Slot {
        #[serde(default)]
        current: Option<Backup>,
        #[serde(default)]
        in_progress: Option<Backup>,
    }
    #[derive(Deserialize)]
    struct Backup {
        id: u64,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        created: Option<String>,
        #[serde(default)]
        finished: Option<String>,
    }
    let resp: Resp = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))?;
    let to_snap = |b: Backup| Snapshot {
        id: b.id.to_string(),
        label: b.label.unwrap_or_else(|| format!("snapshot {}", b.id)),
        created_at: b
            .finished
            .as_deref()
            .or(b.created.as_deref())
            .and_then(linode_time),
        size_gb: None, // Linode doesn't report per-snapshot size on this endpoint.
        status: b.status.unwrap_or_default(),
    };
    let slot = resp.snapshot.unwrap_or(Slot {
        current: None,
        in_progress: None,
    });
    Ok([slot.in_progress, slot.current]
        .into_iter()
        .flatten()
        .map(to_snap)
        .collect())
}

/// Parse a `/account/events` body, keeping only events for `linode_id`, newest first.
fn parse_linode_events(body: &str, linode_id: &str) -> Result<Vec<ServerEvent>> {
    #[derive(Deserialize)]
    struct Page {
        #[serde(default)]
        data: Vec<Event>,
    }
    #[derive(Deserialize)]
    struct Event {
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        created: Option<String>,
        #[serde(default)]
        percent_complete: Option<f64>,
        #[serde(default)]
        entity: Option<Entity>,
    }
    #[derive(Deserialize)]
    struct Entity {
        #[serde(default)]
        id: Option<serde_json::Value>,
        #[serde(default, rename = "type")]
        kind: Option<String>,
    }
    let page: Page = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))?;
    Ok(page
        .data
        .into_iter()
        .filter(|e| {
            let ent = match &e.entity {
                Some(en) => en,
                None => return false,
            };
            if ent.kind.as_deref() != Some("linode") {
                return false;
            }
            // entity.id is a JSON number; compare as a string against our id.
            ent.id
                .as_ref()
                .map(|v| match v {
                    serde_json::Value::Number(n) => n.to_string() == linode_id,
                    serde_json::Value::String(s) => s == linode_id,
                    _ => false,
                })
                .unwrap_or(false)
        })
        .map(|e| ServerEvent {
            action: e.action.unwrap_or_else(|| "event".into()),
            status: e.status.unwrap_or_default(),
            created_at: e.created.as_deref().and_then(linode_time),
            progress: e.percent_complete,
        })
        .collect())
}

#[async_trait]
impl ServerManager for LinodeClient {
    async fn list_all(&self) -> Result<Vec<ServerInfo>> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let resp = self
                .http
                .get(format!("{API}/linode/instances?page={page}&page_size=100"))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(Self::net)?;
            let status = resp.status();
            let text = resp.text().await.map_err(Self::net)?;
            if !status.is_success() {
                return Err(Self::linode_reason(status, &text));
            }
            let (mut servers, pages) = parse_instances_page(&text, |t| self.price_per_hour(t))?;
            out.append(&mut servers);
            if page >= pages {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn metrics(&self, id: &str, _window_secs: u32) -> Result<ServerMetrics> {
        // Linode's stats endpoint always returns ~24h of 5-minute averages; callers trim.
        let resp = self
            .http
            .get(format!("{API}/linode/instances/{id}/stats"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(Self::linode_reason(status, &text));
        }
        parse_stats(&text)
    }

    async fn power(&self, id: &str, action: PowerAction) -> Result<()> {
        let name = match action {
            PowerAction::Boot => "boot",
            PowerAction::Shutdown => "shutdown",
            PowerAction::Reboot => "reboot",
        };
        LinodeClient::power(self, id, name).await
    }

    async fn snapshot(&self, id: &str, label: &str) -> Result<()> {
        // Requires the Backups add-on to be enabled; if it isn't, linode_reason surfaces that.
        let resp = self
            .http
            .post(format!("{API}/linode/instances/{id}/snapshots"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "label": label }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }

    async fn list_snapshots(&self, id: &str) -> Result<Vec<Snapshot>> {
        let resp = self
            .http
            .get(format!("{API}/linode/instances/{id}/backups"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(Self::linode_reason(status, &text));
        }
        parse_linode_backups(&text)
    }

    async fn set_rdns(&self, _id: &str, ip: &str, ptr: &str) -> Result<()> {
        let resp = self
            .http
            .put(format!("{API}/networking/ips/{ip}"))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "rdns": ptr }))
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }

    async fn recent_events(&self, id: &str) -> Result<Vec<ServerEvent>> {
        let resp = self
            .http
            .get(format!("{API}/account/events"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(Self::linode_reason(status, &text));
        }
        parse_linode_events(&text, id)
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[test]
    fn parses_paginated_instances_with_specs() {
        let body = r#"{
          "data": [{
            "id": 777, "region": "us-east", "type": "g6-nanode-1", "status": "running",
            "ipv4": ["50.1.2.3"], "tags": ["sentinel-sync"],
            "label": "sentinel-sync", "ipv6": "2600:db8::1/128",
            "created": "2025-11-02T08:30:00",
            "specs": {"vcpus": 1, "memory": 1024, "disk": 25600}
          }],
          "page": 1, "pages": 3, "results": 21
        }"#;
        let (rows, pages) = parse_instances_page(body, |_| 0.0075).unwrap();
        assert_eq!(pages, 3);
        let s = &rows[0];
        assert_eq!(s.provider, Provider::Linode);
        assert_eq!(s.label, "sentinel-sync");
        assert_eq!(s.state, InstanceState::Running);
        assert_eq!(s.vcpus, 1);
        assert_eq!(s.memory_mb, 1024);
        assert_eq!(s.disk_gb, 25);
        assert!((s.monthly - 5.0).abs() < 1e-9);
        assert_eq!(s.currency, "USD");
        assert!(s.created_at.is_some());
    }

    #[test]
    fn old_minimal_instance_shape_still_parses() {
        // The exact shape list_ephemeral consumes — the new Option fields must not break it.
        let body = r#"{"data": [{"id": 1, "region": "us-east", "type": "g6-nanode-1",
            "status": "offline", "ipv4": [], "tags": ["sentinel-ephemeral"]}], "pages": 1}"#;
        let (rows, pages) = parse_instances_page(body, |_| 0.0075).unwrap();
        assert_eq!(pages, 1);
        assert_eq!(rows[0].state, InstanceState::Stopped);
        assert_eq!(rows[0].label, "1"); // falls back to the id
    }

    #[test]
    fn stats_normalize_ms_timestamps_and_bits() {
        let body = r#"{"data": {
            "cpu": [[1700000000000, 7.5]],
            "netv4": {"in": [[1700000000000, 8000.0]], "out": [[1700000000000, 16000.0]]},
            "io": {"io": [[1700000000000, 42.0]]}
        }, "title": "stats"}"#;
        let m = parse_stats(body).unwrap();
        assert_eq!(m.cpu_pct[0].ts, 1700000000); // ms → s
        assert!((m.cpu_pct[0].value - 7.5).abs() < 1e-9);
        assert!((m.net_in_bps[0].value - 1000.0).abs() < 1e-9); // bits → bytes
        assert!((m.net_out_bps[0].value - 2000.0).abs() < 1e-9);
        assert!((m.disk_io[0].value - 42.0).abs() < 1e-9);
    }

    #[test]
    fn parses_manual_snapshot_slot_in_progress_first() {
        let body = r#"{
          "automatic": [{"id": 1, "label": null, "status": "successful", "type": "auto"}],
          "snapshot": {
            "current": {"id": 900, "label": "release-cut", "status": "successful",
                        "created": "2025-01-01T00:00:00", "finished": "2025-01-01T00:10:00"},
            "in_progress": {"id": 901, "label": "hotfix", "status": "pending",
                            "created": "2025-02-01T00:00:00", "finished": null}
          }
        }"#;
        let snaps = parse_linode_backups(body).unwrap();
        // Only the manual snapshot slot (2 entries), automatic backups excluded, in-progress first.
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].id, "901");
        assert_eq!(snaps[0].label, "hotfix");
        assert_eq!(snaps[0].status, "pending");
        assert_eq!(snaps[1].id, "900");
        // current uses its finished time (00:10), not created (00:00).
        assert_eq!(snaps[1].created_at, linode_time("2025-01-01T00:10:00"));
    }

    #[test]
    fn filters_account_events_to_the_target_linode() {
        let body = r#"{"data": [
            {"action": "linode_reboot", "status": "finished", "percent_complete": 100,
             "created": "2025-03-01T12:00:00", "entity": {"id": 777, "type": "linode", "label": "web"}},
            {"action": "linode_boot", "status": "started", "percent_complete": 30,
             "created": "2025-03-02T12:00:00", "entity": {"id": 888, "type": "linode", "label": "other"}},
            {"action": "account_settings_update", "status": "notification",
             "created": "2025-03-03T12:00:00", "entity": null}
        ]}"#;
        let evs = parse_linode_events(body, "777").unwrap();
        assert_eq!(evs.len(), 1, "only the id=777 linode event");
        assert_eq!(evs[0].action, "linode_reboot");
        assert_eq!(evs[0].status, "finished");
        assert!((evs[0].progress.unwrap() - 100.0).abs() < 1e-9);
        assert_eq!(evs[0].created_at, linode_time("2025-03-01T12:00:00"));
    }
}
