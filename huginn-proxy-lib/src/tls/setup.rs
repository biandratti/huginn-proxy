use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::config::TlsConfig;
use crate::error::Result;

use super::acceptor::build_server_config;
use super::cert_source::{CertSource, StaticCertSource, WatchedCertSource};

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Result of TLS setup.
///
/// `_source` is kept alive for the lifetime of `TlsSetup`. Dropping the
/// setup tears down the certificate source (and its filesystem watcher, in
/// watch mode), which in turn closes the reload channel and lets the
/// reload task exit cleanly.
pub struct TlsSetup {
    pub acceptor: SharedTlsAcceptor,
    _source: CertSource,
}

/// Setup TLS with hot reload support.
///
/// - `watch = false`: certificates are loaded once and never reloaded. No
///   background task is spawned.
/// - `watch = true`: a filesystem watcher monitors cert/key files; on
///   debounced change events, a background task rebuilds the `TlsAcceptor`
///   and swaps it in via `ArcSwap`.
pub async fn setup_tls_with_hot_reload(
    tls_config: &TlsConfig,
    watch: bool,
    watch_delay_secs: u32,
) -> Result<TlsSetup> {
    let source = build_cert_source(tls_config, watch, watch_delay_secs).await?;

    let initial_certs = source.current();
    let initial_server = build_server_config(
        initial_certs.certs.clone(),
        initial_certs.key.clone_key(),
        &tls_config.alpn,
        &tls_config.options,
        &tls_config.client_auth,
        &tls_config.session_resumption,
    )?;
    let tls_acceptor =
        Arc::new(ArcSwap::new(Arc::new(TlsAcceptor::from(Arc::new(initial_server)))));

    if let Some(mut rx) = source.subscribe() {
        let acceptor_for_update = Arc::clone(&tls_acceptor);
        let alpn = tls_config.alpn.clone();
        let options = tls_config.options.clone();
        let client_auth = tls_config.client_auth.clone();
        let session_resumption = tls_config.session_resumption.clone();
        tokio::spawn(async move {
            loop {
                // If the source is dropped, the sender is gone and the
                // channel is closed; exit cleanly instead of spinning.
                if rx.changed().await.is_err() {
                    error!("Certificate source channel closed; hot reload disabled until restart");
                    break;
                }
                let new_certs = rx.borrow().clone();
                match build_server_config(
                    new_certs.certs.clone(),
                    new_certs.key.clone_key(),
                    &alpn,
                    &options,
                    &client_auth,
                    &session_resumption,
                ) {
                    Ok(cfg) => {
                        acceptor_for_update.store(Arc::new(TlsAcceptor::from(Arc::new(cfg))));
                        info!("Certificate reloaded successfully");
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to rebuild TLS acceptor on reload");
                    }
                }
            }
        });
    }

    Ok(TlsSetup { acceptor: tls_acceptor, _source: source })
}

async fn build_cert_source(
    tls_config: &TlsConfig,
    watch: bool,
    watch_delay_secs: u32,
) -> Result<CertSource> {
    let cert_path = PathBuf::from(&tls_config.cert_path);
    let key_path = PathBuf::from(&tls_config.key_path);

    if watch {
        Ok(CertSource::Watched(
            WatchedCertSource::watch(cert_path, key_path, watch_delay_secs).await?,
        ))
    } else {
        Ok(CertSource::Static(
            StaticCertSource::load(
                Path::new(&tls_config.cert_path),
                Path::new(&tls_config.key_path),
            )
            .await?,
        ))
    }
}
