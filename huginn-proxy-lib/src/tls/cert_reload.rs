//! Glue between the proxy's config/telemetry and the config-agnostic
//! [`huginn_certs`] crate.
//!
//! [`huginn_certs::DynamicCertResolver::update`] takes plain [`CertEntry`] values
//! and returns a [`CertReloadReport`] without touching metrics. This module
//! translates configured [`Domain`]s into `CertEntry`s and records the
//! `tls_cert_reload_*` metrics from the report, keeping the crate free of any
//! dependency on `config` or `telemetry`.

use huginn_certs::{CertEntry, CertReloadReport, DynamicCertResolver};
use std::path::PathBuf;
use tracing::info;

use crate::config::Domain;
use crate::telemetry::Metrics;

/// Translate configured domains into cert entries for the resolver.
///
/// Domains that declare both a `cert_path` and a `key_path` become a
/// [`CertEntry`]; a domain missing either is skipped (it can still serve TLS via
/// the catch-all default cert) with an informational log, mirroring the previous
/// in-resolver behaviour.
pub fn cert_entries_from_domains(domains: &[Domain]) -> Vec<CertEntry> {
    let mut entries = Vec::with_capacity(domains.len());
    for domain in domains {
        match (&domain.cert_path, &domain.key_path) {
            (Some(cert_path), Some(key_path)) => entries.push(CertEntry {
                host: domain.host.clone(),
                cert_path: PathBuf::from(cert_path),
                key_path: PathBuf::from(key_path),
                label: domain.label().to_string(),
            }),
            _ => info!(
                host = domain.label(),
                "Domain has no cert_path/key_path; it will serve TLS only if a default certificate exists"
            ),
        }
    }
    entries
}

/// Reload the resolver's certs from `domains` and record reload metrics.
///
/// Success metrics carry each cert's chain hash and are emitted only after the
/// resolver's atomic swap (they come from the returned report), so the gauges
/// never advertise a cert that didn't go into service.
pub async fn reload_certs(
    resolver: &DynamicCertResolver,
    domains: &[Domain],
    metrics: &Metrics,
) -> CertReloadReport {
    let entries = cert_entries_from_domains(domains);
    let report = resolver.update(&entries).await;

    for (label, cert_hash) in &report.loaded {
        metrics.record_tls_cert_reload_success(label, *cert_hash);
    }
    for label in &report.failed {
        metrics.record_tls_cert_reload_error(label);
    }

    report
}
