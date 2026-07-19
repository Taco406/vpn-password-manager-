//! Cloud provider abstraction for ephemeral VPN exit nodes. The real implementation
//! (Linode) lives behind `live-linode`; the mock models the create→boot→run→destroy
//! lifecycle deterministically.

use crate::error::Result;
use async_trait::async_trait;

/// The tag every SENTINEL-created instance carries, so the orphan sweep can find and
/// destroy anything a crash left behind (D10).
pub const EPHEMERAL_TAG: &str = "sentinel-ephemeral";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceState {
    Provisioning,
    Booting,
    Running,
    /// Powered off but still existing (and still billing on Linode). Only a `delete` stops the
    /// meter — a kept-but-stopped node is an intentional, opt-in choice, surfaced with its cost.
    Stopped,
    Deleting,
    Gone,
}

/// A running (or pending) instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub id: String,
    pub region: String,
    pub instance_type: String,
    pub state: InstanceState,
    pub ipv4: Option<String>,
    pub tags: Vec<String>,
}

/// What to create.
#[derive(Clone, Debug)]
pub struct InstanceSpec {
    pub region: String,
    pub instance_type: String,
    /// base64 cloud-init user_data.
    pub user_data: String,
    pub label: String,
}

/// A provider region with hourly price context.
#[derive(Clone, Debug, PartialEq)]
pub struct Region {
    pub id: String,
    pub label: String,
    pub country: String,
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn create(&self, spec: &InstanceSpec) -> Result<Instance>;
    async fn get(&self, id: &str) -> Result<Instance>;
    async fn delete(&self, id: &str) -> Result<()>;
    /// All instances tagged [`EPHEMERAL_TAG`] — used by the orphan sweep.
    async fn list_ephemeral(&self) -> Result<Vec<Instance>>;
    async fn regions(&self) -> Result<Vec<Region>>;
    /// Hourly USD price for an instance type.
    fn price_per_hour(&self, instance_type: &str) -> f64;

    /// Power a node OFF but keep it (it keeps billing until `delete`). Opt-in node lifecycle.
    async fn shutdown(&self, id: &str) -> Result<()>;
    /// Power a stopped node back ON.
    async fn boot(&self, id: &str) -> Result<()>;
    /// Reboot a running node.
    async fn reboot(&self, id: &str) -> Result<()>;
}
