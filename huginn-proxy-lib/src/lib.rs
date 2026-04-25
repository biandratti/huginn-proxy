#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod fingerprinting;
pub mod health_check;
pub mod load_balancing;
pub mod proxy;
pub mod security;
pub mod telemetry;
pub mod tls;

pub use config::{
    load_from_path, Backend, BackendHttpVersion, Config, DynamicConfig, Route, StaticConfig,
    TlsConfig,
};
pub use error::{ProxyError, Result};
pub use fingerprinting::SynResult;
pub use fingerprinting::{forwarded, names, read_client_hello, CapturingStream, Ja4Fingerprints};
pub use health_check::{BackendHealth, HealthRegistry};
pub use load_balancing::RoundRobin;
pub use proxy::reload::{
    initial_client_pool, initial_rate_limiter, try_reload, SharedClientPool, SharedRateLimiter,
};
pub use proxy::server::{SynProbe, WatchOptions};
pub use proxy::{forwarding, run};
pub use telemetry::Metrics;
pub use tls::build_tls_acceptor;
