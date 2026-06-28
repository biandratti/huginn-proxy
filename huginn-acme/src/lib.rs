//! ACME (Let's Encrypt) adapter for huginn-proxy, isolated in its own crate.
//!
//! The returned resolvers implement `rustls_acme::rustls::server::ResolvesServerCert`. Because
//! the workspace resolves a single `rustls` (`0.23.x`, shared with `tokio-rustls` via
//! `futures-rustls`), that trait object is the *same* type the proxy's acceptor expects, so it
//! plugs into the `CompositeResolver` without any trait mismatch.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls_acme::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use rustls_acme::caches::DirCache;
use rustls_acme::rustls::crypto::aws_lc_rs;
use rustls_acme::rustls::server::ResolvesServerCert;
use rustls_acme::rustls::{ClientConfig, RootCertStore};
use rustls_acme::AcmeConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

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
/// `builder_with_provider`, so this never installs a global `CryptoProvider` default —
/// huginn stays free of global crypto state.
///
/// - `directory_url`: overrides the directory; when `None`, picks Let's Encrypt
///   staging/production from `staging`.
/// - `directory_ca_path`: PEM bundle to trust for the **directory** TLS connection instead of the
///   compiled-in webpki roots. Needed for private/test ACME servers (e.g. Pebble) with a
///   self-signed CA; leave `None` for public CAs like Let's Encrypt.
/// - `cancel`: cancelling it makes every spawned task exit at its next poll.
pub fn start_acme(
    contact_email: &str,
    cache_dir: &str,
    staging: bool,
    directory_url: Option<&str>,
    directory_ca_path: Option<&str>,
    domains: &[String],
    cancel: CancellationToken,
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
        // One `AcmeState` (and one cert) per domain. A custom directory CA (Pebble/private)
        // replaces the default webpki client config; otherwise the webpki default is kept.
        let config = match &client_config {
            Some(cc) => AcmeConfig::new_with_client_config([domain.as_str()], cc.clone()),
            None => AcmeConfig::new([domain.as_str()]),
        };
        let mut state = config
            .contact_push(format!("mailto:{contact_email}"))
            .cache(DirCache::new(PathBuf::from(cache_dir)))
            .directory(directory)
            .state();

        let resolver: Arc<dyn ResolvesServerCert> = state.resolver();
        resolvers.push((domain.to_ascii_lowercase(), resolver));

        let host = domain.clone();
        let cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => {
                        info!(domain = %host, "ACME task shutting down");
                        break;
                    }
                    event = state.next() => match event {
                        Some(Ok(ok)) => info!(domain = %host, event = ?ok, "ACME event"),
                        Some(Err(err)) => error!(domain = %host, error = ?err, "ACME error"),
                        None => {
                            info!(domain = %host, "ACME stream ended");
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
