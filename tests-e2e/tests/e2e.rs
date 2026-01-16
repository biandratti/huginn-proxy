//! End-to-end tests for Huginn Proxy
//!
//! These tests require Docker and Docker Compose to be available.
//! They use the Docker Compose configuration from `examples/docker-compose.yml`
//! which includes the proxy and backend services (using `examples/backend/Dockerfile`).
//!
//! To run these tests:
//! 1. Start Docker Compose: `cd examples && docker compose up -d --build`
//! 2. Run tests: `cargo test --package tests-e2e --test e2e`

mod basic;
mod fingerprint_isolation;
mod fingerprints;
mod header_override;
mod health_checks;
mod load_balancing;
mod path_manipulation;
mod tls;
mod tls_cipher_curve_config;
