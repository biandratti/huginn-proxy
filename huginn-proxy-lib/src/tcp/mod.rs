#![forbid(unsafe_code)]

use std::sync::Arc;

use crate::config::Config;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

mod dns;
mod handler;
mod http_peek;
pub mod metrics;

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

    let handler = TcpHandler::new(config, counters);
    handler
        .run(listener, &mut shutdown)
        .await
        .map_err(TcpError::Handler)
}
