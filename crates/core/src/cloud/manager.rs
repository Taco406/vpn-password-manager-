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
}
