//! VPN orchestration: the connect state machine and the orphan sweep. Telemetry
//! (metrics, history, speed test) is added in Phase 4.

pub mod session;
pub mod sweep;

pub use session::{
    connect, disconnect, ConnectDeps, ConnectState, Connection, MockPubkeyFetcher,
    ServerPubkeyFetcher,
};
pub use sweep::orphan_sweep;
