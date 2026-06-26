//! ACME (Let's Encrypt) adapter for huginn-proxy, isolated in its own crate.
//!
//! Mirrors the eBPF boundary (`huginn-proxy-lib` never imports `huginn-ebpf`): primitives
//! in, trait-objects out. This crate depends only on `rustls-acme` and never on
//! `huginn-proxy-lib`, so the smol/`async-io` reactor that `rustls-acme` pulls in stays out
//! of the core library's dependency tree.
//!
//! The returned resolvers implement `rustls_acme::rustls::server::ResolvesServerCert`. Because
//! the workspace resolves a single `rustls` (`0.23.x`, shared with `tokio-rustls` via
//! `futures-rustls`), that trait object is the *same* type the proxy's acceptor expects, so it
//! plugs into the `CompositeResolver` without any trait mismatch.

use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls_acme::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use rustls_acme::caches::DirCache;
use rustls_acme::rustls::server::ResolvesServerCert;
use rustls_acme::AcmeConfig;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Errors returned while wiring up ACME.
///
/// Construction is currently infallible past the empty-domain guard, but the `Result`
/// signature reserves room for future validation without churning callers.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// `start_acme` was called with no domains; the caller should pass `None` instead.
    #[error("no ACME domains provided")]
    NoDomains,
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
/// - `cancel`: cancelling it makes every spawned task exit at its next poll.
pub fn start_acme(
    contact_email: &str,
    cache_dir: &str,
    staging: bool,
    directory_url: Option<&str>,
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

    let mut resolvers = Vec::with_capacity(domains.len());
    let mut tasks = Vec::with_capacity(domains.len());

    for domain in domains {
        // One `AcmeState` (and one cert) per domain, like rpxy-acme.
        let mut state = AcmeConfig::new([domain.as_str()])
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
