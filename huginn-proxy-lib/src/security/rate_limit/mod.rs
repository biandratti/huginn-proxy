//! Rate limiting implementation for Huginn Proxy.
//!
//! The low-level Count-Min Sketch ([`Estimator`]) and the dual-buffer sliding
//! window ([`Rate`]) come from Cloudflare's [`pingora_limits`] crate. This
//! module provides a thin, opinionated wrapper:
//!
//! - [`RateLimiter`] (`limiter.rs`): high-level limiter that combines a
//!   [`Rate`] tracker with limit enforcement and the result type
//!   [`RateLimitResult`].
//! - [`RateLimitManager`] (`manager.rs`): registry of global and per-route
//!   limiters plus key extraction (IP, header, route, combined).
//!
//! # Example Usage
//!
//! ```
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
//!     }
//!     RateLimitResult::Limited { limit, reset_after, .. } => {
//!         println!("Rate limited. Try again in {:?}", reset_after);
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

mod limiter;
mod manager;

pub use limiter::{RateLimitResult, RateLimiter};
pub use manager::{extract_rate_limit_key, RateLimitManager};
pub use pingora_limits::estimator::Estimator;
pub use pingora_limits::rate::Rate;
