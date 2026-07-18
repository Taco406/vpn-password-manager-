//! Region latency probing for the globe picker. The real probe times a TCP connect to
//! each region's speedtest endpoint; the mock returns seeded values.

use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait LatencyProbe: Send + Sync {
    /// Round-trip estimate in milliseconds for a region id.
    async fn probe(&self, region_id: &str) -> Result<u32>;
}

/// Seeded latencies matching the demo regions.
#[derive(Default)]
pub struct MockLatencyProbe;

#[async_trait]
impl LatencyProbe for MockLatencyProbe {
    async fn probe(&self, region_id: &str) -> Result<u32> {
        Ok(match region_id {
            "us-east" => 18,
            "us-west" => 62,
            "eu-central" => 96,
            "eu-west" => 88,
            "ap-south" => 214,
            "ap-northeast" => 156,
            "ap-southeast" => 198,
            "sa-east" => 128,
            _ => 120,
        })
    }
}

/// The real probe: TCP-connect timing to `speedtest.<region>.linode.com:443`.
#[cfg(feature = "live-linode")]
pub struct TcpLatencyProbe;

#[cfg(feature = "live-linode")]
#[async_trait]
impl LatencyProbe for TcpLatencyProbe {
    async fn probe(&self, region_id: &str) -> Result<u32> {
        use std::time::Instant;
        let host = format!("speedtest.{region_id}.linode.com:443");
        let start = Instant::now();
        let _ = tokio::net::TcpStream::connect(&host)
            .await
            .map_err(|e| crate::error::CoreError::Network(e.to_string()))?;
        Ok(start.elapsed().as_millis() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_seeded_values() {
        let p = MockLatencyProbe;
        assert_eq!(p.probe("us-east").await.unwrap(), 18);
        assert_eq!(p.probe("unknown").await.unwrap(), 120);
    }
}
