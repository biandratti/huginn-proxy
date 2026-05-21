use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::config::TlsConfig;
use crate::error::Result;
use crate::telemetry::Metrics;

use super::acceptor::build_server_config;
use super::cert_source::{cert_chain_hash, CertSource, StaticCertSource, WatchedCertSource};

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Result of TLS setup.
///
/// In watch mode the reload background task owns the `CertSource` so the
/// filesystem watcher and its `watch::Sender` stay alive for the lifetime
/// of the task (which itself is alive for the lifetime of the process).
/// `TlsSetup` therefore only needs to expose the shared `TlsAcceptor`.
pub struct TlsSetup {
    pub acceptor: SharedTlsAcceptor,
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
    metrics: Arc<Metrics>,
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

    metrics.record_tls_cert_reload_success(cert_chain_hash(&initial_certs.certs));

    let rx_opt = source.subscribe();
    if let Some(mut rx) = rx_opt {
        let acceptor_for_update = Arc::clone(&tls_acceptor);
        let alpn = tls_config.alpn.clone();
        let options = tls_config.options.clone();
        let client_auth = tls_config.client_auth.clone();
        let session_resumption = tls_config.session_resumption.clone();
        let metrics_for_task = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _source_keep_alive = source;
            loop {
                // TODO: graceful shutdown for the cert reload subsystem is
                // pending and will be tackled in a separate task.
                // Coordinated shutdown for the cert reload subsystem" for the design (modeled after
                // Pingora's `ShutdownWatch = watch::Receiver<bool>` pattern).
                // Until then this loop only exits on the anomaly of the
                // source channel closing mid-process; on normal
                // SIGINT/SIGTERM the task is cancelled by the Tokio runtime.
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
                        metrics_for_task
                            .record_tls_cert_reload_success(cert_chain_hash(&new_certs.certs));
                        info!("TLS acceptor hot-swapped to new certificate");
                    }
                    Err(e) => {
                        metrics_for_task.record_tls_cert_reload_error();
                        error!(error = %e, "Failed to rebuild TLS acceptor on reload");
                    }
                }
            }
        });
    }

    Ok(TlsSetup { acceptor: tls_acceptor })
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
