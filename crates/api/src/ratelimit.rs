//! Token-bucket limiter for the Cognito quota budgets (CLAUDE.md invariant 3).
//!
//! Lives here because both binaries spend from the same non-adjustable
//! budgets — the broker's Describe limiter and the controller's audit loop are
//! two slices of one `UserPoolClientRead` allowance — and the two slices
//! should be measured the same way.
//!
//! Runtime-agnostic on purpose: [`RateLimiter::try_acquire`] never blocks. It
//! either spends a token or says how long until one is available, and the
//! caller decides whether to wait (the controller's audit loop) or fail fast
//! with a retryable error (the broker's request path, where queueing would
//! turn a throttle into a latency spike for every caller behind it).

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RateLimiter {
    rate_per_sec: f64,
    burst: f64,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    tokens: f64,
    last: Instant,
    /// Set by [`RateLimiter::back_off`]: no tokens are granted before this.
    paused_until: Option<Instant>,
}

impl RateLimiter {
    /// `rate_per_sec` sustained, with bursts up to `burst` (at least 1).
    pub fn new(rate_per_sec: f64, burst: u32) -> Self {
        assert!(
            rate_per_sec > 0.0 && rate_per_sec.is_finite(),
            "rate must be positive"
        );
        let burst = f64::from(burst.max(1));
        RateLimiter {
            rate_per_sec,
            burst,
            state: Mutex::new(State {
                tokens: burst,
                last: Instant::now(),
                paused_until: None,
            }),
        }
    }

    pub fn rate_per_sec(&self) -> f64 {
        self.rate_per_sec
    }

    /// Spend one token, or return how long until one will be available.
    pub fn try_acquire(&self) -> Result<(), Duration> {
        self.try_acquire_at(Instant::now())
    }

    fn try_acquire_at(&self, now: Instant) -> Result<(), Duration> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(until) = s.paused_until {
            if now < until {
                return Err(until - now);
            }
            s.paused_until = None;
        }
        let elapsed = now.saturating_duration_since(s.last).as_secs_f64();
        s.tokens = (s.tokens + elapsed * self.rate_per_sec).min(self.burst);
        s.last = now;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - s.tokens) / self.rate_per_sec,
            ))
        }
    }

    /// Stop granting tokens for `pause` and drain the bucket. Called when AWS
    /// says `TooManyRequests`: the budget is account-wide, so a throttle means
    /// someone else needs it more than we do right now — yield.
    pub fn back_off(&self, pause: Duration) {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.tokens = 0.0;
        s.last = now;
        let until = now + pause;
        s.paused_until = Some(s.paused_until.map_or(until, |u| u.max(until)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bucket_grants_its_burst_then_refuses() {
        let limiter = RateLimiter::new(1.0, 3);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(limiter.try_acquire_at(now).is_ok());
        }
        let wait = limiter.try_acquire_at(now).unwrap_err();
        assert!(wait <= Duration::from_secs(1) && wait > Duration::ZERO);
    }

    #[test]
    fn tokens_refill_at_the_configured_rate_and_cap_at_burst() {
        let limiter = RateLimiter::new(2.0, 1);
        let t0 = Instant::now();
        assert!(limiter.try_acquire_at(t0).is_ok());
        assert!(limiter.try_acquire_at(t0).is_err());
        assert!(
            limiter
                .try_acquire_at(t0 + Duration::from_millis(500))
                .is_ok()
        );
        // A long idle period does not bank more than `burst`.
        let later = t0 + Duration::from_secs(60);
        assert!(limiter.try_acquire_at(later).is_ok());
        assert!(limiter.try_acquire_at(later).is_err());
    }

    #[test]
    fn back_off_yields_the_budget() {
        let limiter = RateLimiter::new(100.0, 10);
        limiter.back_off(Duration::from_secs(30));
        let wait = limiter.try_acquire().unwrap_err();
        assert!(wait > Duration::from_secs(29));
    }
}
