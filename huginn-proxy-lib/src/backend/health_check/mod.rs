//! Active backend health checks.
//!
//! This module proactively probes backends and rejects requests targeting
//! known-unhealthy ones with a 502 Bad Gateway, instead of letting the request
//! propagate the failure to the client (which usually means a multi-second
//! TCP connect timeout). The design intentionally mirrors `rust-rpxy` —
//! consecutive-failure thresholds with hysteresis, no full circuit-breaker
//! state machine — and is documented in detail in `data/analisys.md` §14–15.
//!
//! ## Anatomy
//!
//! | Component | Role |
//! |---|---|
//! | [`BackendHealth`] | Per-backend `AtomicBool` shared between the checker task and request handlers. |
//! | [`HealthRegistry`] | Address → [`BackendHealth`] map; cheap-to-clone read handle for the forwarding gate. |
//! | [`ConsecutiveCounter`] | State-transition engine with hysteresis; owned by each checker task. |
//! | [`check_tcp`] | TCP 3-way handshake probe. |
//! | `HealthCheckSupervisor` *(coming in PR3)* | Owns the probe `tokio::JoinHandle`s; reacts to hot reload. |
//! | `check_http` *(coming in PR4)* | HTTP `GET /path` probe with expected-status validation. |
//!
//! ## Backwards compatibility
//!
//! Backends without a `[backends.health_check]` block are not registered,
//! and [`HealthRegistry::is_healthy`] returns `true` for any unknown address.
//! Existing configurations therefore behave identically — health checks are
//! strictly opt-in.

// `counter` and `check_tcp` are pure-logic primitives consumed by the
// `HealthCheckSupervisor` arriving in PR3. They are re-exported below so
// integration tests can import them normally; the `dead_code` allow keeps
// `cargo build` clean until the supervisor is wired in.
#[allow(dead_code)]
mod check_tcp;
#[allow(dead_code)]
mod counter;
mod health;
mod registry;

pub use check_tcp::check_tcp;
pub use counter::ConsecutiveCounter;
pub use health::BackendHealth;
pub use registry::HealthRegistry;
