//! Vault health: reused / weak / old passwords, plus HIBP breach checking via
//! k-anonymity (only a 5-char SHA-1 prefix ever leaves the device).

pub mod audit;
pub mod hibp;

pub use audit::{run_audit, AuditReport, ReusedGroup};
pub use hibp::{HibpClient, MockHibp};

#[cfg(feature = "live-hibp")]
pub use hibp::RealHibp;
