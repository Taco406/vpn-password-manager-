//! Current-network info, for auto-connect on untrusted SSIDs (allowlist manager).

use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait NetInfo: Send + Sync {
    /// The current Wi-Fi SSID, if on Wi-Fi.
    async fn current_ssid(&self) -> Result<Option<String>>;
}

/// Returns a fixed SSID for tests/the demo.
pub struct MockNetInfo {
    pub ssid: Option<String>,
}

impl Default for MockNetInfo {
    fn default() -> Self {
        MockNetInfo {
            ssid: Some("home".into()),
        }
    }
}

#[async_trait]
impl NetInfo for MockNetInfo {
    async fn current_ssid(&self) -> Result<Option<String>> {
        Ok(self.ssid.clone())
    }
}

/// Should the VPN auto-connect on this SSID given a trusted allowlist? Any network not
/// in the allowlist is treated as untrusted.
pub fn should_auto_connect(current: Option<&str>, trusted_allowlist: &[String]) -> bool {
    match current {
        None => false,
        Some(ssid) => !trusted_allowlist.iter().any(|t| t == ssid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn untrusted_ssid_triggers_auto_connect() {
        let trusted = vec!["home".to_string(), "office".to_string()];
        assert!(!should_auto_connect(Some("home"), &trusted));
        assert!(should_auto_connect(Some("airport-wifi"), &trusted));
        assert!(!should_auto_connect(None, &trusted));
    }

    #[tokio::test]
    async fn mock_returns_ssid() {
        let ni = MockNetInfo::default();
        assert_eq!(ni.current_ssid().await.unwrap(), Some("home".into()));
    }
}
