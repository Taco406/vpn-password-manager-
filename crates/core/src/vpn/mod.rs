//! VPN orchestration: the connect state machine, orphan sweep, live telemetry
//! (metrics, cost, speed test), local session history, and connection profiles.

pub mod cost;
pub mod history;
pub mod metrics;
pub mod profiles;
pub mod session;
pub mod speedtest;
pub mod sweep;

pub use cost::{accrued_usd, CostTicker};
pub use history::{
    build_report, totals, HistoryStore, MonthlyReport, RegionBreakdown, SessionRecord, Totals,
};
pub use metrics::{sample_at, total_rx_bytes, MetricsSample, UpsizeDetector};
pub use profiles::{seeded as seeded_profiles, ConnectionProfile};
pub use session::{
    connect, disconnect, ConnectDeps, ConnectState, Connection, MockPubkeyFetcher,
    ServerPubkeyFetcher,
};
pub use speedtest::{MockSpeedTest, SpeedResult, SpeedTest};
pub use sweep::{orphan_sweep, orphan_sweep_keeping};
