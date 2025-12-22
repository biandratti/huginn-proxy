//! Core library for Huginn reverse proxy.
#![forbid(unsafe_code)]

pub mod config;
pub mod tcp;
pub use tcp::metrics::serve_prometheus_metrics;
pub use tcp::metrics::ConnectionCount;
