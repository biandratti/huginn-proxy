//! Library surface for the eBPF agent (config, telemetry, health checks).
//!
//! The binary in `main.rs` is a thin wrapper; integration tests live under `tests/`.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod healthchecks;
pub mod telemetry;
