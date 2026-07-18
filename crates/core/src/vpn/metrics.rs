//! Live session metrics: WireGuard throughput merged with the exit node's CPU/RAM/NIC
//! (pushed over the tunnel every 3s by the metrics agent). Plus the "consider a larger
//! instance" detector: sustained high CPU for a window arms a one-tap upsize.

use super::super::wg::{cumulative_bytes, throughput_rate};
use serde::{Deserialize, Serialize};

/// One merged metrics sample.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSample {
    /// instantaneous bytes/sec
    pub rx: f64,
    pub tx: f64,
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub nic_pct: f64,
    pub latency_ms: f64,
    /// seconds since connect
    pub t: f64,
}

/// Deterministic sample at time `t` — the source of truth the frontend mirrors.
pub fn sample_at(t: f64) -> MetricsSample {
    let rx = throughput_rate(t);
    let tx = rx / 6.0;
    // CPU tracks utilization of a ~1Gbps NIC on a Nanode; nudged by a slow sine.
    let nic_pct = ((rx / 118_000_000.0) * 100.0).min(100.0); // 1Gbps ≈ 118 MB/s
    let cpu_pct = (nic_pct * 0.7 + 12.0 + 8.0 * (t / 13.0).sin()).clamp(0.0, 100.0);
    let mem_pct = (28.0 + 5.0 * (t / 40.0).sin()).clamp(0.0, 100.0);
    let latency_ms = 18.0 + 4.0 * (t / 5.0).sin().abs();
    MetricsSample {
        rx,
        tx,
        cpu_pct,
        mem_pct,
        nic_pct,
        latency_ms,
        t,
    }
}

/// Total bytes transferred by time `t` (rx), for session totals.
pub fn total_rx_bytes(t: f64) -> u64 {
    cumulative_bytes(t)
}

/// Detects sustained high CPU to suggest a larger instance next session. Feed it
/// samples; it fires once CPU has stayed above the threshold for the whole window.
pub struct UpsizeDetector {
    threshold_pct: f64,
    window_secs: f64,
    high_since: Option<f64>,
    fired: bool,
}

impl UpsizeDetector {
    /// Brief default: >85% for 60s.
    pub fn new() -> Self {
        UpsizeDetector {
            threshold_pct: 85.0,
            window_secs: 60.0,
            high_since: None,
            fired: false,
        }
    }

    pub fn with(threshold_pct: f64, window_secs: f64) -> Self {
        UpsizeDetector {
            threshold_pct,
            window_secs,
            high_since: None,
            fired: false,
        }
    }

    /// Returns true exactly once, when the suggestion first arms.
    pub fn observe(&mut self, sample: &MetricsSample) -> bool {
        if self.fired {
            return false;
        }
        if sample.cpu_pct >= self.threshold_pct {
            match self.high_since {
                None => self.high_since = Some(sample.t),
                Some(since) if sample.t - since >= self.window_secs => {
                    self.fired = true;
                    return true;
                }
                _ => {}
            }
        } else {
            self.high_since = None;
        }
        false
    }

    pub fn armed(&self) -> bool {
        self.fired
    }
}

impl Default for UpsizeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_fields_in_range() {
        for i in 0..500 {
            let s = sample_at(i as f64);
            assert!((0.0..=100.0).contains(&s.cpu_pct));
            assert!((0.0..=100.0).contains(&s.nic_pct));
            assert!(s.rx >= 0.0);
        }
    }

    #[test]
    fn upsize_fires_after_sustained_high_cpu() {
        let mut d = UpsizeDetector::with(85.0, 60.0);
        // Below threshold: never fires.
        for t in 0..30 {
            assert!(!d.observe(&MetricsSample {
                cpu_pct: 50.0,
                t: t as f64,
                rx: 0.0,
                tx: 0.0,
                mem_pct: 0.0,
                nic_pct: 0.0,
                latency_ms: 0.0,
            }));
        }
        // High but not yet a full window.
        let mut fired = false;
        for t in 100..200 {
            let f = d.observe(&MetricsSample {
                cpu_pct: 92.0,
                t: t as f64,
                rx: 0.0,
                tx: 0.0,
                mem_pct: 0.0,
                nic_pct: 0.0,
                latency_ms: 0.0,
            });
            if f {
                fired = true;
                // Should fire around t=160 (60s after t=100).
                assert!((160..=161).contains(&t));
                break;
            }
        }
        assert!(fired, "detector never fired");
        assert!(d.armed());
    }

    #[test]
    fn high_cpu_resets_if_it_dips() {
        let mut d = UpsizeDetector::with(85.0, 60.0);
        d.observe(&MetricsSample {
            cpu_pct: 90.0,
            t: 0.0,
            rx: 0.0,
            tx: 0.0,
            mem_pct: 0.0,
            nic_pct: 0.0,
            latency_ms: 0.0,
        });
        // Dip resets the window.
        d.observe(&MetricsSample {
            cpu_pct: 40.0,
            t: 30.0,
            rx: 0.0,
            tx: 0.0,
            mem_pct: 0.0,
            nic_pct: 0.0,
            latency_ms: 0.0,
        });
        // Not enough sustained time after reset.
        assert!(!d.observe(&MetricsSample {
            cpu_pct: 90.0,
            t: 70.0,
            rx: 0.0,
            tx: 0.0,
            mem_pct: 0.0,
            nic_pct: 0.0,
            latency_ms: 0.0
        }));
        assert!(!d.armed());
    }
}
