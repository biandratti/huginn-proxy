#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod fingerprinting;
pub mod load_balancing;
pub mod proxy;
pub mod telemetry;
pub mod tls;

pub use config::{load_from_path, Backend, BackendHttpVersion, Config, Route, TlsConfig};
pub use error::{ProxyError, Result};
pub use fingerprinting::{forwarded, names, read_client_hello, CapturingStream};
pub use load_balancing::RoundRobin;
pub use proxy::{forwarding, run};
pub use tls::build_rustls;
