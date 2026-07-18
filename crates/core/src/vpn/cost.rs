//! Live session cost ticker: hourly rate × elapsed.

/// Accrued cost for a session running `elapsed_secs` at `hourly_usd`.
pub fn accrued_usd(hourly_usd: f64, elapsed_secs: f64) -> f64 {
    hourly_usd * (elapsed_secs / 3600.0)
}

/// A tiny helper the UI polls for the cost ticker.
#[derive(Clone, Copy, Debug)]
pub struct CostTicker {
    pub hourly_usd: f64,
    pub started_at: i64,
}

impl CostTicker {
    pub fn new(hourly_usd: f64, started_at: i64) -> Self {
        CostTicker {
            hourly_usd,
            started_at,
        }
    }

    pub fn accrued(&self, now: i64) -> f64 {
        accrued_usd(self.hourly_usd, (now - self.started_at).max(0) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accrues_linearly() {
        // One hour at a Nanode's hourly rate.
        assert!((accrued_usd(0.0075, 3600.0) - 0.0075).abs() < 1e-12);
        assert!((accrued_usd(0.0075, 1800.0) - 0.00375).abs() < 1e-12);
        assert_eq!(accrued_usd(0.0075, 0.0), 0.0);
    }

    #[test]
    fn ticker_clamps_negative_elapsed() {
        let t = CostTicker::new(0.036, 1000);
        assert_eq!(t.accrued(500), 0.0);
        assert!(t.accrued(1000 + 3600) > 0.0);
    }
}
