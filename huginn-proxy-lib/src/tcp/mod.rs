#![forbid(unsafe_code)]

use std::sync::Arc;

use crate::config::{Config, Mode};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

mod dns;
pub mod fingerprint;
mod handler;
mod http_peek;
pub mod metrics;
mod tls;

pub use handler::TcpHandler;
pub use metrics::{ConnectionCount, ConnectionSnapshot};

#[derive(Debug, Error)]
pub enum TcpError {
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    #[error("handler error: {0}")]
    Handler(String),
}

pub async fn run(
    config: Arc<Config>,
    counters: Arc<ConnectionCount>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TcpError> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(TcpError::Bind)?;
    info!(addr = ?config.listen, "tcp listener bound");

    let tls_acceptor = if matches!(config.mode, Mode::TlsTermination) {
        let tls_cfg = config
            .tls
            .as_ref()
            .ok_or_else(|| TcpError::Handler("tls config required for tls_termination".into()))?;
        Some(
            tls::build_tls_acceptor(&tls_cfg.cert_path, &tls_cfg.key_path, &tls_cfg.alpn)
                .map_err(TcpError::Handler)?,
        )
    } else {
        None
    };

    let handler = TcpHandler::new(config, counters, tls_acceptor);
    handler
        .run(listener, &mut shutdown)
        .await
        .map_err(TcpError::Handler)
}
