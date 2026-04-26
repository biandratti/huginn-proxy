//! End-to-end tests for Huginn Proxy
//!
//! These tests require Docker and Docker Compose to be available.
//! They use the Docker Compose configuration from `examples/docker-compose.ebpf.yml`
//!
//! To run these tests:
//! 1. Start Docker Compose: `cd examples && docker compose -f docker-compose.ebpf.yml up -d --build`
//! 2. Run tests: `cargo test --package tests-e2e --test e2e`

mod basic;
mod fingerprint_akamai;
mod fingerprint_isolation;
mod fingerprint_ja4;
mod fingerprint_sync_tcp;
mod header_override;
mod health_checks;
mod load_balance;
mod path_manipulation;
mod security_headers;
mod tls;
mod tls_cipher_curve_config;
