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
//! ## Recommended usage
//!
//! Health checks are configured per backend via `[backends.health_check]` and
//! are strictly opt-in.
//!
//! - Use them when Huginn Proxy is the main resiliency layer (VM/bare metal,
//!   Docker Compose, or direct upstream addresses).
//! - They are usually less useful when routing only through an orchestrator
//!   service VIP (e.g. Kubernetes `Service`), where pod readiness is already
//!   managed by the platform.
//!
//! Backends without a `[backends.health_check]` block are treated as healthy
//! by default.

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
