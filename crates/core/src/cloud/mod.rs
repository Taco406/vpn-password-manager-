//! Ephemeral exit-node provisioning: the provider abstraction, a deterministic mock,
//! the real Linode client (feature-gated), and region latency probing.

pub mod latency;
pub mod manager;
pub mod mock;
pub mod provider;

#[cfg(feature = "live-hetzner")]
pub mod hetzner;
#[cfg(feature = "live-linode")]
pub mod linode;

pub use latency::{LatencyProbe, MockLatencyProbe};
pub use manager::{MetricPoint, PowerAction, Provider, ServerInfo, ServerManager, ServerMetrics};
pub use mock::{MockCloud, MockServerManager};
pub use provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
    PERSISTENT_VPN_TAG, SYNC_TAG,
};

#[cfg(feature = "live-hetzner")]
pub use hetzner::HetznerClient;
#[cfg(feature = "live-linode")]
pub use linode::LinodeClient;
