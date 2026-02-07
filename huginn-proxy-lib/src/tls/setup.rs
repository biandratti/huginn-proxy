use crate::config::TlsConfig;
use crate::error::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use super::{build_cert_reloader, build_rustls};

pub struct TlsSetup {
    /// TLS acceptor wrapped in Arc<RwLock> for thread-safe hot reload
    pub acceptor: Arc<RwLock<Option<TlsAcceptor>>>,
}

/// Setup TLS with hot reload support
///
/// This function:
/// 1. Builds the initial TLS acceptor from configuration (synchronous)
/// 2. Sets up certificate hot reload monitoring (async - waits for ReloaderService initialization)
/// 3. Spawns background tasks for certificate reloading
///
/// Returns a `TlsSetup` containing the TLS acceptor.
/// The reloader service runs in background tasks and doesn't need to be returned.
pub async fn setup_tls_with_hot_reload(tls_config: &TlsConfig) -> Result<TlsSetup> {
    let initial_acceptor = build_rustls(tls_config)?;
    let tls_acceptor = Arc::new(RwLock::new(Some(initial_acceptor)));

    // Setup certificate reloader (async - initializes filesystem watcher)
    let mut reloader_rx = build_cert_reloader(tls_config).await?;
    let alpn = tls_config.alpn.clone();
    let tls_options = tls_config.options.clone();
    let session_resumption = tls_config.session_resumption.clone();

    let tls_acceptor_for_update = Arc::clone(&tls_acceptor);
    tokio::spawn(async move {
        loop {
            let _ = reloader_rx.changed().await;
            let certs_keys = reloader_rx.borrow().clone();
            if let Some(certs_keys) = certs_keys {
                match certs_keys.build_tls_acceptor(&alpn, &tls_options, &session_resumption) {
                    Ok(new_acceptor) => {
                        info!("Certificate reloaded successfully");
                        *tls_acceptor_for_update.write().await = Some(new_acceptor);
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to build TLS acceptor from reloaded certificates");
                    }
                }
            } else {
                warn!("Certificate reloader returned None, keeping current certificates");
            }
        }
    });

    Ok(TlsSetup { acceptor: tls_acceptor })
}
