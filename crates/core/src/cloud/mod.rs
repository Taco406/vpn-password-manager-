//! Ephemeral exit-node provisioning: the provider abstraction, a deterministic mock,
//! the real Linode client (feature-gated), and region latency probing.

pub mod latency;
pub mod mock;
pub mod provider;

#[cfg(feature = "live-linode")]
pub mod linode;

pub use latency::{LatencyProbe, MockLatencyProbe};
pub use mock::MockCloud;
pub use provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
    PERSISTENT_VPN_TAG, SYNC_TAG,
};

#[cfg(feature = "live-linode")]
pub use linode::LinodeClient;
