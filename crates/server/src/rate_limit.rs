//! In-memory per-username login rate limiter.
//!
//! Tracks failed login attempts per username and enforces a lockout window
//! after a configurable number of failures. State is stored in a `DashMap`
//! so it is shared across all Axum handler tasks without an external mutex.

use std::time::Instant;

use dashmap::DashMap;

/// Tracks failed login attempt timestamps for a single username.
#[derive(Debug, Clone)]
struct AttemptRecord {
    /// Timestamps of recent failed login attempts.
    failures: Vec<Instant>,
}

/// Thread-safe, in-memory login rate limiter keyed by username.
#[derive(Debug)]
pub struct LoginRateLimiter {
    /// Map from username → attempt record.
    attempts: DashMap<String, AttemptRecord>,
    /// Maximum failed attempts within the window before lockout.
    max_attempts: u32,
    /// Lockout/window duration in seconds.
    window_seconds: u64,
}

impl LoginRateLimiter {
    /// Create a new rate limiter with the given thresholds.
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            attempts: DashMap::new(),
            max_attempts,
            window_seconds,
        }
    }

    /// Check whether the given username is currently rate-limited.
    ///
    /// Returns `true` if the user has exceeded `max_attempts` failed logins
    /// within the last `window_seconds` and should be denied.
    pub fn is_rate_limited(&self, username: &str) -> bool {
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(self.window_seconds))
            .unwrap_or(Instant::now());

        if let Some(mut record) = self.attempts.get_mut(username) {
            // Prune expired entries
            record.failures.retain(|t| *t >= cutoff);
            record.failures.len() >= self.max_attempts as usize
        } else {
            false
        }
    }

    /// Record a failed login attempt for the given username.
    ///
    /// Returns the number of failures within the current window (after pruning).
    pub fn record_failure(&self, username: &str) -> u32 {
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(self.window_seconds))
            .unwrap_or(Instant::now());

        let mut entry = self
            .attempts
            .entry(username.to_string())
            .or_insert_with(|| AttemptRecord {
                failures: Vec::new(),
            });

        // Prune expired entries
        entry.failures.retain(|t| *t >= cutoff);

        // Record the new failure
        entry.failures.push(Instant::now());

        entry.failures.len() as u32
    }

    /// Reset (clear) the failure counter for a username, e.g. after successful login.
    pub fn reset(&self, username: &str) {
        self.attempts.remove(username);
    }

    /// Remove all entries whose failure timestamps are entirely outside the
    /// current window. Call this periodically (e.g. from a background task)
    /// to prevent unbounded memory growth from attackers sending many
    /// distinct usernames.
    pub fn cleanup_stale_entries(&self) {
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(self.window_seconds))
            .unwrap_or(Instant::now());

        self.attempts.retain(|_username, record| {
            record.failures.retain(|t| *t >= cutoff);
            !record.failures.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_attempts_is_not_limited() {
        let limiter = LoginRateLimiter::new(3, 60);
        assert!(!limiter.is_rate_limited("alice"));
    }

    #[test]
    fn test_below_threshold_is_not_limited() {
        let limiter = LoginRateLimiter::new(3, 60);
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        assert!(!limiter.is_rate_limited("alice"));
    }

    #[test]
    fn test_at_threshold_is_limited() {
        let limiter = LoginRateLimiter::new(3, 60);
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        assert!(limiter.is_rate_limited("alice"));
    }

    #[test]
    fn test_reset_clears_counter() {
        let limiter = LoginRateLimiter::new(3, 60);
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        assert!(limiter.is_rate_limited("alice"));

        limiter.reset("alice");
        assert!(!limiter.is_rate_limited("alice"));
    }

    #[test]
    fn test_different_users_independent() {
        let limiter = LoginRateLimiter::new(2, 60);
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        assert!(limiter.is_rate_limited("alice"));
        assert!(!limiter.is_rate_limited("bob"));
    }

    #[test]
    fn test_expired_window_allows_retry() {
        // Use a window of 0 seconds so all attempts are immediately expired
        let limiter = LoginRateLimiter::new(2, 0);
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        limiter.record_failure("alice");
        // With a 0-second window, all attempts should be pruned immediately
        // on the next check
        assert!(!limiter.is_rate_limited("alice"));
    }
}
