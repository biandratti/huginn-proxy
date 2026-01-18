//! High-level rate limiter implementation.
//!
//! This module provides a convenient wrapper around the low-level Rate tracker
//! with rate limiting logic and result types.

use crate::security::rate_limit::rate::Rate;
use std::hash::Hash;
use std::time::Duration;

/// Result of a rate limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed to proceed.
    Allowed {
        /// Maximum number of requests allowed in the window
        limit: isize,
        /// Number of requests remaining in the current window
        remaining: isize,
    },
    /// Request is rate limited and should be rejected.
    Limited {
        /// Maximum number of requests allowed in the window
        limit: isize,
        /// Number of requests remaining (always 0)
        remaining: isize,
        /// Time until the rate limit resets
        reset_after: Duration,
    },
}

impl RateLimitResult {
    /// Returns true if the request is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }

    /// Returns true if the request is limited.
    pub fn is_limited(&self) -> bool {
        matches!(self, RateLimitResult::Limited { .. })
    }

    /// Get the limit value.
    pub fn limit(&self) -> isize {
        match self {
            RateLimitResult::Allowed { limit, .. } => *limit,
            RateLimitResult::Limited { limit, .. } => *limit,
        }
    }

    /// Get the remaining count.
    pub fn remaining(&self) -> isize {
        match self {
            RateLimitResult::Allowed { remaining, .. } => *remaining,
            RateLimitResult::Limited { remaining, .. } => *remaining,
        }
    }

    /// Get the reset duration if limited.
    pub fn reset_after(&self) -> Option<Duration> {
        match self {
            RateLimitResult::Limited { reset_after, .. } => Some(*reset_after),
            _ => None,
        }
    }
}

/// A rate limiter that enforces request limits over time windows.
///
/// # Example
/// ```ignore
/// use std::time::Duration;
/// use huginn_proxy_lib::security::rate_limit::RateLimiter;
///
/// let limiter = RateLimiter::new(100, 200, Duration::from_secs(1));
///
/// match limiter.check(&"192.168.1.1") {
///     RateLimitResult::Allowed { remaining, .. } => {
///         println!("Request allowed, {} remaining", remaining);
///     }
///     RateLimitResult::Limited { reset_after, .. } => {
///         println!("Rate limited, retry after {:?}", reset_after);
///     }
/// }
/// ```
pub struct RateLimiter {
    rate_tracker: Rate,
    max_requests: isize,
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Parameters
    /// - `requests_per_second`: Base rate limit (used for rate calculation)
    /// - `burst`: Maximum number of requests allowed in a burst
    /// - `window`: Time window for rate limiting
    ///
    /// # Example
    /// ```ignore
    /// // Allow 100 requests per second with burst of 200
    /// let limiter = RateLimiter::new(100, 200, Duration::from_secs(1));
    /// ```
    pub fn new(_requests_per_second: u32, burst: u32, window: Duration) -> Self {
        Self { rate_tracker: Rate::new(window), max_requests: burst as isize, window }
    }

    /// Check if a request should be allowed or rate limited.
    ///
    /// This method records the request and returns whether it should be allowed.
    /// If you need to check without recording, use `check_only` instead.
    ///
    /// # Parameters
    /// - `key`: Identifier for the entity being rate limited (e.g., IP address, API key)
    ///
    /// # Returns
    /// `RateLimitResult` indicating whether the request is allowed or limited
    pub fn check<T: Hash>(&self, key: &T) -> RateLimitResult {
        let current = self.rate_tracker.observe(key, 1);

        if current > self.max_requests {
            RateLimitResult::Limited {
                limit: self.max_requests,
                remaining: 0,
                reset_after: self.window,
            }
        } else {
            RateLimitResult::Allowed {
                limit: self.max_requests,
                remaining: self.max_requests.saturating_sub(current),
            }
        }
    }

    /// Check rate limit without recording the request.
    ///
    /// This is useful for read-only checks or when you want to check
    /// before committing to processing the request.
    ///
    /// # Parameters
    /// - `key`: Identifier for the entity being rate limited
    ///
    /// # Returns
    /// `RateLimitResult` indicating whether a request would be allowed
    pub fn check_only<T: Hash>(&self, key: &T) -> RateLimitResult {
        let current = self.rate_tracker.observe(key, 0); // Observe with 0 to not increment

        if current >= self.max_requests {
            RateLimitResult::Limited {
                limit: self.max_requests,
                remaining: 0,
                reset_after: self.window,
            }
        } else {
            RateLimitResult::Allowed {
                limit: self.max_requests,
                remaining: self.max_requests.saturating_sub(current),
            }
        }
    }

    /// Get the current rate for a key (requests per second).
    ///
    /// This returns the rate from the previous completed window.
    pub fn current_rate<T: Hash>(&self, key: &T) -> f64 {
        self.rate_tracker.rate(key)
    }

    /// Get the configured maximum requests (burst limit).
    pub fn max_requests(&self) -> isize {
        self.max_requests
    }

    /// Get the configured window duration.
    pub fn window(&self) -> Duration {
        self.window
    }
}
