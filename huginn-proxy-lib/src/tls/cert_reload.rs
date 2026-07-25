//! Glue between the proxy's config/telemetry and the config-agnostic
//! [`huginn_certs`] crate.
//!
//! [`build_server_crypto`] takes plain [`CertEntry`] values plus
//! [`TlsBuildOptions`] and returns a [`ServerCryptoMap`] + [`CertReloadReport`]
//! without touching metrics. This module translates configured [`Domain`]s into
//! `CertEntry`s and records the `tls_cert_reload_*` metrics from the report,
//! keeping the crate free of any dependency on `config` or `telemetry`.

use huginn_certs::{
    build_server_crypto, CertEntry, CertReloadReport, CryptoFileSource, ServerCryptoMap,
    TlsBuildOptions,
};
use std::sync::Arc;
use tracing::{error, info};

use crate::config::Domain;
use crate::error::{ProxyError, Result};
use crate::telemetry::Metrics;
use crate::tls::setup::SharedServerCrypto;

/// Translate configured domains into cert entries for the per-SNI config builder.
///
/// Domains that declare both a `cert_path` and a `key_path` become a
/// [`CertEntry`]; a domain missing either is skipped (it can still serve TLS via
/// the catch-all default cert) with an informational log.
///
/// A domain that also sets `client_ca_path` gets that CA attached to its source,
/// so its per-SNI `ServerConfig` enforces mutual TLS while other domains do not —
/// client authentication is per-domain, not listener-wide.
pub fn cert_entries_from_domains(domains: &[Domain]) -> Vec<CertEntry> {
    let mut entries = Vec::with_capacity(domains.len());
    for domain in domains {
        match (&domain.cert_path, &domain.key_path) {
            (Some(cert_path), Some(key_path)) => {
                let mut source = CryptoFileSource::new(cert_path, key_path);
                if let Some(ca) = &domain.client_ca_path {
                    source = source.with_client_ca(ca);
                }
                entries.push(CertEntry {
                    host: domain.host.clone(),
                    source: Arc::new(source),
                    label: domain.label().to_string(),
                });
            }
            _ => info!(
                host = domain.label(),
                "Domain has no cert_path/key_path; it will serve TLS only if a default certificate exists"
            ),
        }
    }
    entries
}

/// Build a [`ServerCryptoMap`] from `domains` and record reload metrics.
///
/// `previous` carries forward a domain's last-good config when its new cert fails
/// to build (best-effort, per-domain). Success metrics carry each cert's chain
/// hash and come from the returned report. Returns `Err` only for process-wide
/// setup failures (ticketer/provider), which are fatal at startup.
pub async fn build_server_crypto_map(
    domains: &[Domain],
    options: &TlsBuildOptions,
    previous: Option<&ServerCryptoMap>,
    metrics: &Metrics,
) -> Result<(ServerCryptoMap, CertReloadReport)> {
    let entries = cert_entries_from_domains(domains);
    let (map, report) = build_server_crypto(&entries, options, previous)
        .await
        .map_err(|e| ProxyError::Tls(e.to_string()))?;

    for (label, cert_hash) in &report.loaded {
        metrics.record_tls_cert_reload_success(label, *cert_hash);
    }
    for label in &report.failed {
        metrics.record_tls_cert_reload_error(label);
    }

    Ok((map, report))
}

/// Rebuild the per-SNI config map from `domains` and swap it in atomically.
///
/// The current map is used as `previous`, so a domain whose cert fails to reload
/// keeps its last-good `ServerConfig`. On a process-wide build failure the swap is
/// skipped and the previous map stays live (fail-safe), reported as an empty
/// [`CertReloadReport`] so the caller does not advertise any change.
pub async fn reload_server_crypto(
    shared: &SharedServerCrypto,
    domains: &[Domain],
    options: &TlsBuildOptions,
    metrics: &Metrics,
) -> CertReloadReport {
    let previous = shared.load_full();
    match build_server_crypto_map(domains, options, Some(&previous), metrics).await {
        Ok((map, report)) => {
            shared.store(Arc::new(map));
            report
        }
        Err(e) => {
            error!(error = %e, "TLS config rebuild failed on reload; keeping previous configs");
            CertReloadReport::default()
        }
    }
}
