#![forbid(unsafe_code)]

pub mod connection;
pub mod handler;
pub mod listener;
pub mod stream;

use std::sync::Arc;

use crate::config::Config;
use handler::TcpHandler;
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Debug, Error)]
pub enum TcpError {
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    #[error("handler error: {0}")]
    Handler(String),
}

pub async fn run(config: Arc<Config>) -> Result<(), TcpError> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(TcpError::Bind)?;
    info!(addr = ?config.listen, "tcp listener bound");

    let handler = TcpHandler::new(config);
    handler.run(listener).await.map_err(TcpError::Handler)
}
