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

    // Setup certificate reloader (async - initializes ReloaderService with filesystem watcher)
    let (reloader_service, reloader_rx) = build_cert_reloader(tls_config).await?;
    let alpn = tls_config.alpn.clone();

    let reloader_service_arc = Arc::new(reloader_service);
    let reloader_service_for_spawn = Arc::clone(&reloader_service_arc);
    tokio::spawn(async move {
        if let Err(e) = reloader_service_for_spawn.start().await {
            warn!(error = %e, "Certificate reloader service exited");
        }
    });

    let tls_acceptor_for_update = Arc::clone(&tls_acceptor);
    let mut reloader_rx_for_spawn = reloader_rx.clone();
    tokio::spawn(async move {
        loop {
            let _ = reloader_rx_for_spawn.changed().await;
            let server_crypto_base = reloader_rx_for_spawn.borrow().clone();
            if let Some(server_crypto_base) = server_crypto_base {
                match server_crypto_base.get_tls_acceptor(&alpn) {
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
