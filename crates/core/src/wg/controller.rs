//! Bringing tunnels up/down and reading counters. The real controller wraps the OS
//! WireGuard implementation (WireGuardNT / wireguard-go); the mock is a deterministic
//! traffic simulator for tests and the demo.

use super::config::ClientConf;
use crate::error::Result;
use async_trait::async_trait;

/// Live tunnel counters (cumulative bytes + last handshake age).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WgCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs: u64,
}

#[async_trait]
pub trait WgController: Send + Sync {
    async fn up(&self, conf: &ClientConf) -> Result<()>;
    async fn down(&self) -> Result<()>;
    async fn counters(&self, elapsed_secs: f64) -> Result<WgCounters>;
}

/// Deterministic traffic waveform shared with the frontend mock bridge so the demo and
/// the tests agree byte-for-byte. Instantaneous throughput (bytes/sec) at `t` seconds:
///
/// `rate(t) = base + a*sin(t/7) + b*sin(t/2.3) + c*sin(t/11)`  (clamped ≥ 0)
///
/// with fixed coefficients. Cumulative bytes is the analytic integral so counters are
/// monotonic and reproducible. This exact formula is mirrored in
/// `apps/desktop/src/bridge/mock/vpnSim.ts` (a golden test compares samples).
pub fn throughput_rate(t: f64) -> f64 {
    let base = 6_000_000.0; // ~6 MB/s baseline
    let a = 3_500_000.0;
    let b = 1_800_000.0;
    let c = 2_200_000.0;
    (base + a * (t / 7.0).sin() + b * (t / 2.3).sin() + c * (t / 11.0).sin()).max(0.0)
}

/// Analytic cumulative bytes = integral of `throughput_rate` from 0 to `t`.
pub fn cumulative_bytes(t: f64) -> u64 {
    // ∫ base dt = base*t; ∫ k*sin(t/p) dt = -k*p*cos(t/p) (+ k*p at 0)
    let base = 6_000_000.0;
    let terms = [(3_500_000.0, 7.0), (1_800_000.0, 2.3), (2_200_000.0, 11.0)];
    let mut total = base * t;
    for (k, p) in terms {
        total += k * p * (1.0 - (t / p).cos());
    }
    total.max(0.0) as u64
}

/// The deterministic mock controller.
#[derive(Default)]
pub struct MockWgController {
    up: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl WgController for MockWgController {
    async fn up(&self, _conf: &ClientConf) -> Result<()> {
        self.up.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        self.up.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn counters(&self, elapsed_secs: f64) -> Result<WgCounters> {
        let rx = cumulative_bytes(elapsed_secs);
        Ok(WgCounters {
            rx_bytes: rx,
            tx_bytes: rx / 6,
            last_handshake_secs: (elapsed_secs as u64) % 30,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counters_are_monotonic() {
        let c = MockWgController::default();
        let mut last = 0u64;
        for t in [0.0, 1.0, 5.0, 30.0, 120.0, 600.0] {
            let counters = c.counters(t).await.unwrap();
            assert!(counters.rx_bytes >= last, "rx not monotonic at t={t}");
            last = counters.rx_bytes;
        }
    }

    #[test]
    fn rate_is_non_negative() {
        for i in 0..1000 {
            assert!(throughput_rate(i as f64 * 0.5) >= 0.0);
        }
    }

    #[test]
    fn cumulative_matches_rate_direction() {
        // Cumulative should increase roughly with the baseline over a second.
        let a = cumulative_bytes(100.0);
        let b = cumulative_bytes(101.0);
        assert!(b > a);
    }

    #[tokio::test]
    async fn up_down_toggles() {
        let c = MockWgController::default();
        let conf = ClientConf {
            client_private_key: "x".into(),
            client_address: "10.66.0.2/32".into(),
            dns: "1.1.1.1".into(),
            server_public_key: "y".into(),
            server_endpoint: "z:1".into(),
            allowed_ips: super::super::config::full_tunnel(),
            keepalive: 25,
        };
        c.up(&conf).await.unwrap();
        c.down().await.unwrap();
    }
}
