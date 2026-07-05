//! ACME (Let's Encrypt) adapter for huginn-proxy, isolated in its own crate.
//!
//! The returned resolvers implement `rustls_acme::rustls::server::ResolvesServerCert`. Because
//! the workspace resolves a single `rustls` (`0.23.x`, shared with `tokio-rustls` via
//! `futures-rustls`), that trait object is the *same* type the proxy's acceptor expects, so it
//! plugs into the `CompositeResolver` without any trait mismatch.

#![forbid(unsafe_code)]

pub mod dir_cache;

use std::sync::Arc;

use futures_util::StreamExt;
use rustls_acme::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use rustls_acme::rustls::crypto::aws_lc_rs;
use rustls_acme::rustls::server::ResolvesServerCert;
use rustls_acme::rustls::{ClientConfig, RootCertStore};
use rustls_acme::AcmeConfig;
use rustls_acme::EventOk;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::dir_cache::DirCache;

/// Callback invoked for every ACME state-machine event.
///
/// Receives `(domain, event)`. Designed for metrics injection following the `SynProbe`
/// boundary pattern: `huginn-acme` stays decoupled from the metrics crate; the binary wires
/// in a closure that calls `Metrics`.
pub type OnAcmeEvent = Arc<dyn Fn(&str, AcmeEvent) + Send + Sync>;

/// A normalized, metrics-ready view of one ACME state-machine event.
///
/// This type is intentionally **decoupled from Prometheus / OpenTelemetry**: `huginn-acme`
/// does not depend on `huginn-proxy-lib` or any metrics crate. The binary (`huginn-proxy`)
/// receives these via the `on_event` callback and translates them into `Metrics` calls,
/// same boundary discipline as `SynProbe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeEvent {
    /// A brand-new certificate was issued or renewed and hot-swapped into the resolver.
    /// This is the primary signal for the renewal-success counter.
    DeployedNewCert,
    /// A previously-cached certificate was loaded from disk at startup.
    /// Does not count as a renewal; it is a successful startup signal.
    DeployedCachedCert,
    /// The certificate or ACME account was persisted to the on-disk cache.
    CacheStored,
    /// Any error in the issuance / renewal / cache cycle.
    Error,
}

/// Errors returned while wiring up ACME.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// `start_acme` was called with no domains; the caller should pass `None` instead.
    #[error("no ACME domains provided")]
    NoDomains,
    /// The directory CA bundle could not be read from disk.
    #[error("failed to read ACME directory CA bundle '{path}': {source}")]
    DirectoryCaRead {
        /// Path that failed to read.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The directory CA bundle could not be parsed as PEM certificates.
    #[error("failed to parse ACME directory CA bundle '{path}': {source}")]
    DirectoryCaParse {
        /// Path that failed to parse.
        path: String,
        /// Underlying PEM parse error.
        source: rustls_pki_types::pem::Error,
    },
    /// The directory CA bundle parsed but contained no certificates.
    #[error("ACME directory CA bundle '{path}' contained no certificates")]
    DirectoryCaEmpty {
        /// Path that contained no certificates.
        path: String,
    },
    /// Building the rustls client config for the ACME directory failed.
    #[error("failed to build ACME directory TLS config: {0}")]
    DirectoryTls(#[from] rustls_acme::rustls::Error),
    /// The ACME cache directory is not writable. Without write access the proxy would
    /// obtain a certificate from the CA and then silently fail to persist it, burning
    /// rate-limit quota on every restart.
    #[error("ACME cache directory not writable for domain '{domain}' at '{path}': {source}")]
    CacheNotWritable {
        /// Domain whose cache directory failed the write check.
        domain: String,
        /// Cache directory path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Build a rustls [`ClientConfig`] that trusts **only** the CA(s) in `ca_path` (PEM) for the
/// ACME directory connection. Used for private/test ACME servers (e.g. Pebble) whose CA is not
/// in the compiled-in webpki roots. Pins the workspace's `aws-lc-rs` provider so it matches the
/// rest of huginn's TLS stack (no global `CryptoProvider` default is installed).
fn directory_client_config(ca_path: &str) -> Result<Arc<ClientConfig>, AcmeError> {
    let bytes = std::fs::read(ca_path)
        .map_err(|source| AcmeError::DirectoryCaRead { path: ca_path.to_string(), source })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|source| AcmeError::DirectoryCaParse { path: ca_path.to_string(), source })?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    if certs.is_empty() {
        return Err(AcmeError::DirectoryCaEmpty { path: ca_path.to_string() });
    }

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }

    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Handles produced by [`start_acme`].
///
/// One `(host, resolver)` pair per ACME domain so the caller can route by SNI, plus the
/// background tasks that drive issuance and renewal.
pub struct AcmeHandles {
    /// `(host, resolver)` per ACME domain. `host` is lowercased for case-insensitive SNI
    /// lookup, matching the convention of the proxy's static `DynamicCertResolver`.
    pub resolvers: Vec<(String, Arc<dyn ResolvesServerCert>)>,
    /// Background tasks driving each `AcmeState` (issuance + renewal). The caller registers
    /// these with its shutdown machinery and cancels them via the [`CancellationToken`]
    /// passed to [`start_acme`].
    pub tasks: Vec<JoinHandle<()>>,
}

/// Start one ACME state machine per exact domain (separate certs, rpxy-acme style).
///
/// `rustls-acme` (feature `aws-lc-rs`) threads the crypto provider explicitly via
/// `builder_with_provider`, so this never installs a global `CryptoProvider` default.
/// huginn stays free of global crypto state.
///
/// - `directory_url`: overrides the directory; when `None`, picks Let's Encrypt
///   staging/production from `staging`.
/// - `directory_ca_path`: PEM bundle to trust for the **directory** TLS connection instead of the
///   compiled-in webpki roots. Needed for private/test ACME servers (e.g. Pebble) with a
///   self-signed CA; leave `None` for public CAs like Let's Encrypt.
/// - `cancel`: cancelling it makes every spawned task exit at its next poll.
/// - `on_event`: optional [`OnAcmeEvent`] callback invoked on every state-machine event.
///   Tracing logs are always emitted regardless of whether a callback is provided.
///
/// # Errors
///
/// Returns [`AcmeError::CacheNotWritable`] if any domain's cache directory cannot be written to.
/// This check runs before spawning any task, so a misconfigured `cache_dir` fails fast at startup
/// instead of silently losing issued certificates and burning CA rate-limit quota.
#[allow(clippy::too_many_arguments)]
pub async fn start_acme(
    contact_email: &str,
    cache_dir: &str,
    staging: bool,
    directory_url: Option<&str>,
    directory_ca_path: Option<&str>,
    domains: &[String],
    cancel: CancellationToken,
    on_event: Option<OnAcmeEvent>,
) -> Result<AcmeHandles, AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::NoDomains);
    }

    let directory = directory_url.unwrap_or(if staging {
        LETS_ENCRYPT_STAGING_DIRECTORY
    } else {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
    });

    // Built once and shared across domains; `None` keeps rustls-acme's default webpki roots.
    let client_config = match directory_ca_path {
        Some(path) => Some(directory_client_config(path)?),
        None => None,
    };

    let mut resolvers = Vec::with_capacity(domains.len());
    let mut tasks = Vec::with_capacity(domains.len());

    for domain in domains {
        // One `DirCache` per domain (per-domain cert subdir, shared accounts subdir).
        // Verify write access before spawning any task: a missing or read-only cache_dir
        // would let the ACME flow succeed, then silently fail to persist the cert, burning
        // LE rate-limit quota on every restart.
        let cache = DirCache::new(cache_dir, domain.as_str());
        cache
            .verify_write_permissions()
            .await
            .map_err(|source| AcmeError::CacheNotWritable {
                domain: domain.clone(),
                path: cache_dir.to_string(),
                source,
            })?;

        // One `AcmeState` (and one cert) per domain. A custom directory CA (Pebble/private)
        // replaces the default webpki client config; otherwise the webpki default is kept.
        let config = match &client_config {
            Some(cc) => AcmeConfig::new_with_client_config([domain.as_str()], cc.clone()),
            None => AcmeConfig::new([domain.as_str()]),
        };
        let mut state = config
            .contact_push(format!("mailto:{contact_email}"))
            .cache(cache)
            .directory(directory)
            .state();

        let resolver: Arc<dyn ResolvesServerCert> = state.resolver();
        resolvers.push((domain.to_ascii_lowercase(), resolver));

        let host = domain.clone();
        let cancel = cancel.clone();
        let cb: Option<OnAcmeEvent> = on_event.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => {
                        info!(domain = %host, "ACME task shutting down");
                        break;
                    }
                    event = state.next() => match event {
                        Some(Ok(ok)) => {
                            let acme_event = acme_event_from_ok(&ok);
                            info!(domain = %host, event = ?ok, "ACME event");
                            if let Some(ref f) = cb {
                                f(&host, acme_event);
                            }
                        }
                        Some(Err(ref err)) => {
                            error!(domain = %host, error = ?err, "ACME error");
                            if let Some(ref f) = cb {
                                f(&host, AcmeEvent::Error);
                            }
                        }
                        None => {
                            warn!(domain = %host, "ACME stream ended unexpectedly");
                            break;
                        }
                    },
                }
            }
        });
        tasks.push(task);
    }

    Ok(AcmeHandles { resolvers, tasks })
}

/// Map a `rustls-acme` [`EventOk`] to our decoupled [`AcmeEvent`].
pub fn acme_event_from_ok(ok: &EventOk) -> AcmeEvent {
    match ok {
        EventOk::DeployedNewCert => AcmeEvent::DeployedNewCert,
        EventOk::DeployedCachedCert => AcmeEvent::DeployedCachedCert,
        EventOk::CertCacheStore | EventOk::AccountCacheStore => AcmeEvent::CacheStored,
    }
}
