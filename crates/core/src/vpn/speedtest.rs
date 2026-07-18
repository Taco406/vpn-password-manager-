//! On-demand speed test through the tunnel. The real implementation downloads/uploads
//! a blob against the exit node's metrics endpoint; the mock is deterministic.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedResult {
    pub down_mbps: f64,
    pub up_mbps: f64,
    pub latency_ms: f64,
}

#[async_trait]
pub trait SpeedTest: Send + Sync {
    /// Run a speed test against the exit node identified by `region_id`.
    async fn run(&self, region_id: &str) -> Result<SpeedResult>;
}

/// Deterministic mock keyed by region (matches the seeded region medians).
#[derive(Default)]
pub struct MockSpeedTest;

#[async_trait]
impl SpeedTest for MockSpeedTest {
    async fn run(&self, region_id: &str) -> Result<SpeedResult> {
        let (down, lat) = match region_id {
            "us-east" => (912.0, 18.0),
            "us-west" => (861.0, 62.0),
            "eu-central" => (903.0, 96.0),
            "eu-west" => (889.0, 88.0),
            "ap-northeast" => (804.0, 156.0),
            "ap-southeast" => (688.0, 198.0),
            "sa-east" => (671.0, 128.0),
            _ => (750.0, 120.0),
        };
        Ok(SpeedResult {
            down_mbps: down,
            up_mbps: down * 0.4,
            latency_ms: lat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_is_deterministic_per_region() {
        let st = MockSpeedTest;
        let a = st.run("us-east").await.unwrap();
        let b = st.run("us-east").await.unwrap();
        assert_eq!(a, b);
        assert!(a.down_mbps > a.up_mbps);
        assert!(st.run("eu-central").await.unwrap().latency_ms > a.latency_ms);
    }
}
