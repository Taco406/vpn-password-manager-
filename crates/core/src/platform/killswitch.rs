//! Kill switch: block all egress except the WireGuard endpoint, so a tunnel drop can't
//! leak traffic. Real implementations use WFP (Windows) and pf (macOS) — documented in
//! docs/architecture.md. The mock records state for tests.

use crate::error::Result;
use async_trait::async_trait;

/// The WireGuard endpoint permitted while the kill switch is engaged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedEndpoint {
    pub ip: String,
    pub port: u16,
}

#[async_trait]
pub trait KillSwitch: Send + Sync {
    /// Block all egress except `allow` (the WG endpoint). Idempotent.
    async fn engage(&self, allow: &AllowedEndpoint) -> Result<()>;
    /// Restore normal networking.
    async fn release(&self) -> Result<()>;
    async fn is_engaged(&self) -> bool;
}

/// Records engage/release for tests and the demo.
#[derive(Default)]
pub struct MockKillSwitch {
    engaged: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl KillSwitch for MockKillSwitch {
    async fn engage(&self, _allow: &AllowedEndpoint) -> Result<()> {
        self.engaged
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn release(&self) -> Result<()> {
        self.engaged
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn is_engaged(&self) -> bool {
        self.engaged.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engage_release_toggles() {
        let ks = MockKillSwitch::default();
        assert!(!ks.is_engaged().await);
        ks.engage(&AllowedEndpoint {
            ip: "203.0.113.7".into(),
            port: 51820,
        })
        .await
        .unwrap();
        assert!(ks.is_engaged().await);
        ks.release().await.unwrap();
        assert!(!ks.is_engaged().await);
    }
}
