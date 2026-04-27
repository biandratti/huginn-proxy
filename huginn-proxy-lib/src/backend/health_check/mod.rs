//! Active backend health checks.
//!
//! This module proactively probes backends and rejects requests targeting
//! known-unhealthy ones with a 502 Bad Gateway, instead of letting the request
//! propagate the failure to the client (which usually means a multi-second
//! TCP connect timeout).
//!
//! ## Anatomy
//!
//! | Component | Role |
//! |---|---|
//! | [`UpstreamHealth`] | Per-upstream `AtomicBool` shared between the checker task and request handlers. |
//! | [`HealthRegistry`] | Address → [`UpstreamHealth`] map; cheap-to-clone read handle for the forwarding gate. |
//! | [`ConsecutiveCounter`] | State-transition engine with hysteresis; owned by each checker task. |
//! | [`check_tcp`] | TCP 3-way handshake probe. |
//! | [`check_http`](check_http::check_http) | HTTP `GET` over `http://{address}{path}` with expected status. |
//! | [`HealthCheckSupervisor`] | Owns the probe `tokio::JoinHandle`s; reconciles on hot reload and shutdown. |
//!
//! ## Backwards compatibility
//!
//! Backends without a `[backends.health_check]` block are not registered,
//! and [`HealthRegistry::is_healthy`] returns `true` for any unknown address.
//! Existing configurations therefore behave identically — health checks are
//! strictly opt-in.

// `counter`, `check_tcp`, and `check_http` are used by `HealthCheckSupervisor`
// and re-exported for integration tests.
mod check_http;
mod check_tcp;
mod checker;
mod counter;
mod health;
mod registry;

pub use check_http::check_http;
pub use check_http::HealthCheckHttpClient;
pub use check_tcp::check_tcp;
pub use checker::HealthCheckSupervisor;
pub use counter::ConsecutiveCounter;
pub use health::UpstreamHealth;
pub use registry::HealthRegistry;
