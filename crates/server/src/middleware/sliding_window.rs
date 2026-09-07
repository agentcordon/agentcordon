//! A fixed-window counter keyed by string, for limits where every request
//! spends budget (as opposed to the device-approve limiter, which counts
//! failures only).

use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    count: u32,
    window_start: Instant,
}

/// Allows `max` hits per `window` for each key.
#[derive(Debug)]
pub struct SlidingWindowLimiter {
    max: u32,
    window: Duration,
    buckets: DashMap<String, Bucket>,
}

impl SlidingWindowLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            buckets: DashMap::new(),
        }
    }

    /// Record one hit for `key`. Returns `Some(retry_after_secs)` when the
    /// key is over budget for the current window; the hit is then refused
    /// and not counted.
    pub fn hit(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut entry = self.buckets.entry(key.to_string()).or_insert(Bucket {
            count: 0,
            window_start: now,
        });
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= self.window {
            entry.count = 0;
            entry.window_start = now;
        }
        if entry.count >= self.max {
            let remaining = self.window.saturating_sub(elapsed).as_secs().max(1);
            return Some(remaining);
        }
        entry.count += 1;
        None
    }

    /// Drop buckets whose window has fully elapsed.
    pub fn cleanup_stale_entries(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.duration_since(b.window_start) < self.window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_the_hit_after_max_within_the_window() {
        let limiter = SlidingWindowLimiter::new(3, Duration::from_secs(60));
        assert_eq!(limiter.hit("a"), None);
        assert_eq!(limiter.hit("a"), None);
        assert_eq!(limiter.hit("a"), None);
        assert!(limiter.hit("a").is_some());
        assert_eq!(limiter.hit("b"), None, "keys are independent");
    }

    #[test]
    fn a_refused_hit_does_not_extend_the_window() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_millis(20));
        assert_eq!(limiter.hit("a"), None);
        assert!(limiter.hit("a").is_some());
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(limiter.hit("a"), None, "window rolled over");
    }
}
