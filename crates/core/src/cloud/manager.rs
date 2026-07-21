//! Multi-provider server management: list EVERY server on an account (not just NorthKey's
//! tagged nodes), read real utilization metrics, and drive power actions. This is a separate
//! capability from [`super::provider::CloudProvider`] on purpose — the VPN connect/sweep
//! machinery keeps its narrow, tag-scoped view, and nothing returned by [`ServerManager::
//! list_all`] is ever fed to the orphan sweeper.

use crate::error::Result;
use async_trait::async_trait;

use super::provider::InstanceState;

/// Which cloud a server lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Linode,
    Hetzner,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Linode => "linode",
            Provider::Hetzner => "hetzner",
        }
    }
}

/// A power action a user can take from the Servers screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerAction {
    Boot,
    Shutdown,
    Reboot,
}

/// One server, normalized across providers.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerInfo {
    pub provider: Provider,
    pub id: String,
    pub label: String,
    pub region: String,
    pub instance_type: String,
    pub state: InstanceState,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub tags: Vec<String>,
    /// Unix seconds, when known.
    pub created_at: Option<i64>,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub disk_gb: u32,
    pub hourly: f64,
    pub monthly: f64,
    /// "USD" (Linode) or "EUR" (Hetzner) — never sum across currencies.
    pub currency: &'static str,
}

/// One sample of a metric time series. `ts` is unix SECONDS.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricPoint {
    pub ts: i64,
    pub value: f64,
}

/// Normalized utilization series: CPU in percent, network in BYTES/second (Linode reports
/// bits/s and is converted), disk in provider-native IO units (blocks/s on Linode, IOPS-ish
/// on Hetzner) — the UI labels it generically.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerMetrics {
    pub cpu_pct: Vec<MetricPoint>,
    pub net_in_bps: Vec<MetricPoint>,
    pub net_out_bps: Vec<MetricPoint>,
    pub disk_io: Vec<MetricPoint>,
}

/// A point-in-time snapshot/image of a server, normalized across providers.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub id: String,
    pub label: String,
    /// Unix seconds, when known.
    pub created_at: Option<i64>,
    /// Stored size in GB, when the provider reports it.
    pub size_gb: Option<f64>,
    /// Provider status string (e.g. "available", "creating").
    pub status: String,
}

/// One recent server activity/action, normalized across providers.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerEvent {
    /// What happened (e.g. "create_image", "reboot", "linode_boot").
    pub action: String,
    /// Provider status string (e.g. "success", "running", "error").
    pub status: String,
    /// Unix seconds, when known.
    pub created_at: Option<i64>,
    /// Completion percent (0–100), when the provider reports it.
    pub progress: Option<f64>,
}

/// Full-account server management. Implemented by `LinodeClient` (alongside `CloudProvider`)
/// and `HetznerClient`.
#[async_trait]
pub trait ServerManager: Send + Sync {
    /// Every server on the account, across all pages. NEVER wired into the orphan sweep.
    async fn list_all(&self) -> Result<Vec<ServerInfo>>;
    /// Utilization series covering roughly the last `window_secs` seconds (best effort —
    /// Linode's stats endpoint always returns ~24h; callers trim client-side).
    async fn metrics(&self, id: &str, window_secs: u32) -> Result<ServerMetrics>;
    /// Boot / graceful shutdown / reboot.
    async fn power(&self, id: &str, action: PowerAction) -> Result<()>;

    // --- Stage 3 lifecycle (v0.1.42). Default to "not supported" so a provider that lacks a
    // capability compiles and reports cleanly; each client overrides what it supports. ---

    /// Take a point-in-time snapshot/image of the server, labelled `label`.
    async fn snapshot(&self, _id: &str, _label: &str) -> Result<()> {
        Err(not_supported())
    }
    /// List the server's snapshots/images, newest first.
    async fn list_snapshots(&self, _id: &str) -> Result<Vec<Snapshot>> {
        Err(not_supported())
    }
    /// Set the reverse-DNS (PTR) record for `ip` to `ptr`.
    async fn set_rdns(&self, _id: &str, _ip: &str, _ptr: &str) -> Result<()> {
        Err(not_supported())
    }
    /// Turn delete/rebuild protection on or off (Hetzner). Linode has no per-instance protection.
    async fn set_protection(&self, _id: &str, _on: bool) -> Result<()> {
        Err(not_supported())
    }
    /// Recent activity/actions for the server, newest first.
    async fn recent_events(&self, _id: &str) -> Result<Vec<ServerEvent>> {
        Err(not_supported())
    }
}

/// The uniform "this provider can't do that" error the default trait methods return.
fn not_supported() -> crate::error::CoreError {
    crate::error::CoreError::Network("not supported by this provider".into())
}
