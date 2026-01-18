//! Rate limiting implementation for Huginn Proxy.
//!
//! This module provides efficient, lock-free rate limiting using algorithms
//! adapted from Cloudflare's Pingora proxy. It uses:
//!
//! - **Count-Min Sketch**: Probabilistic data structure for frequency estimation
//! - **Sliding Window**: Dual-buffer approach for smooth rate tracking
//! - **Atomic Operations**: Lock-free implementation for high concurrency
//!
//! # Architecture
//!
//! The rate limiting system consists of three main components:
//!
//! 1. **Estimator** (`estimator.rs`): Count-Min Sketch implementation for
//!    tracking event frequencies.
//!
//! 2. **Rate** (`rate.rs`): Sliding window rate tracker using dual buffers
//!    (red/blue slots) that swap atomically at interval boundaries.
//!
//! 3. **RateLimiter** (`limiter.rs`): High-level rate limiter that combines
//!    the rate tracker with limit enforcement logic.
//!
//! # Example Usage
//!
//! ```ignore
//! use huginn_proxy_lib::security::rate_limit::{RateLimiter, RateLimitResult};
//! use std::time::Duration;
//!
//! // Create a rate limiter: 100 rps with burst of 200
//! let limiter = RateLimiter::new(100, 200, Duration::from_secs(1));
//!
//! // Check if a request should be allowed
//! match limiter.check(&"192.168.1.1") {
//!     RateLimitResult::Allowed { limit, remaining } => {
//!         println!("Request allowed. {}/{} remaining", remaining, limit);
//!         // Process request...
//!     }
//!     RateLimitResult::Limited { limit, reset_after, .. } => {
//!         println!("Rate limited. Try again in {:?}", reset_after);
//!         // Return 429 Too Many Requests
//!     }
//! }
//! ```
//!
//! # Configuration
//!
//! Rate limiting can be configured globally or per-route via TOML:
//!
//! ```toml
//! [security.rate_limit]
//! enabled = true
//! requests_per_second = 100
//! burst = 200
//! limit_by = "ip"
//!
//! [[routes]]
//! prefix = "/api"
//! rate_limit = { requests_per_second = 50, burst = 100 }
//! ```

mod estimator;
mod limiter;
mod rate;

pub use limiter::{RateLimitResult, RateLimiter};

pub use rate::Rate;

use ahash::RandomState;
use std::hash::Hash;

#[inline]
fn hash<T: Hash>(key: T, hasher: &RandomState) -> u64 {
    hasher.hash_one(key)
}
