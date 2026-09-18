#![forbid(unsafe_code)]

pub mod backend;
pub mod config;
pub mod error;
pub mod fingerprinting;
pub mod proxy;
pub mod security;
pub mod telemetry;
pub mod tls;
pub(crate) mod utils;

pub use backend::{
    BackendSelector, HealthCheckSupervisor, HealthRegistry, RoundRobin, UpstreamHealth,
};
pub use config::{
    Backend, BackendHttpVersion, Config, DynamicConfig, Route, StaticConfig, TlsConfig,
    load_from_path,
};
pub use error::{ProxyError, Result};
pub use fingerprinting::SynResult;
pub use fingerprinting::{CapturingStream, Ja4Fingerprints, forwarded, names, read_client_hello};
pub use proxy::reload::{
    SharedClientPool, SharedRateLimiter, initial_client_pool, initial_rate_limiter, try_reload,
};
pub use proxy::server::{SynProbe, WatchOptions};
pub use proxy::shutdown::{ShutdownPhase, ShutdownSender, ShutdownWatch, shutdown_channel};
pub use proxy::{forwarding, run};
pub use telemetry::{GateState, Metrics, NotReadyReason, Readiness, ReadinessGate};
