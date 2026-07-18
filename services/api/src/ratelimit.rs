//! A small in-memory sliding-window rate limiter (SECURITY.md T9). Keeps the auth and
//! unlock endpoints from being brute-forced without pulling a heavier dependency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns true if the action keyed by `key` is allowed: at most `max` hits within
    /// the trailing `window`. Records the hit when allowed.
    pub fn check(&self, key: &str, max: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let hits = map.entry(key.to_string()).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max {
            false
        } else {
            hits.push(now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks() {
        let rl = RateLimiter::new();
        let w = Duration::from_secs(60);
        for _ in 0..5 {
            assert!(rl.check("k", 5, w));
        }
        assert!(!rl.check("k", 5, w), "6th hit must be blocked");
        // A different key is independent.
        assert!(rl.check("other", 5, w));
    }
}
