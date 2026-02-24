#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod fingerprinting;
pub mod load_balancing;
pub mod proxy;
pub mod security;
pub mod telemetry;
pub mod tls;

pub use config::{load_from_path, Backend, BackendHttpVersion, Config, Route, TlsConfig};
pub use error::{ProxyError, Result};
pub use fingerprinting::SynResult;
pub use fingerprinting::{forwarded, names, read_client_hello, CapturingStream, Ja4Fingerprints};
pub use load_balancing::RoundRobin;
pub use proxy::server::SynProbe;
pub use proxy::{forwarding, run};
pub use tls::build_tls_acceptor;
