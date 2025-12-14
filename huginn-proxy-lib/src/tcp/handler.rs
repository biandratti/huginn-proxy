#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{Backend, Config};
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

pub struct TcpHandler {
    config: Arc<Config>,
    backend_idx: Mutex<usize>,
}

impl TcpHandler {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config, backend_idx: Mutex::new(0) }
    }

    pub async fn run(&self, listener: TcpListener) -> Result<(), String> {
        loop {
            let (client, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "failed to accept connection");
                    continue;
                }
            };
            let backend = match self.next_backend() {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "failed to select backend");
                    continue;
                }
            };
            let cfg = self.config.clone();
            tokio::spawn(handle_conn(cfg, client, backend, addr));
        }
    }

    fn next_backend(&self) -> Result<Backend, String> {
        let mut guard = self
            .backend_idx
            .lock()
            .map_err(|_| "backend_idx mutex poisoned".to_string())?;
        let len = self.config.backends.len();
        if len == 0 {
            return Err("no backends configured".into());
        }
        let idx = if *guard < len { *guard } else { 0 };
        let backend = self
            .config
            .backends
            .get(idx)
            .cloned()
            .ok_or_else(|| "backend index out of range".to_string())?;
        // advance round-robin without modulo to appease clippy: reset manually
        *guard = match guard.checked_add(1) {
            Some(next) if next < len => next,
            _ => 0,
        };
        Ok(backend)
    }
}

async fn handle_conn(
    config: Arc<Config>,
    client: TcpStream,
    backend: Backend,
    client_addr: std::net::SocketAddr,
) {
    let connect_timeout = Duration::from_millis(config.timeouts.connect_ms);
    let idle_timeout = Duration::from_millis(config.timeouts.idle_ms);

    info!(%client_addr, backend = %backend.address, "accepted connection");

    let upstream = match timeout(connect_timeout, TcpStream::connect(&backend.address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(%client_addr, backend = %backend.address, error = %e, "failed to connect to backend");
            return;
        }
        Err(_) => {
            warn!(%client_addr, backend = %backend.address, "connect timeout");
            return;
        }
    };

    if let Err(e) = bidirectional_copy(client, upstream, idle_timeout).await {
        warn!(%client_addr, backend = %backend.address, error = %e, "forwarding ended with error");
    } else {
        info!(%client_addr, backend = %backend.address, "connection closed");
    }
}

async fn bidirectional_copy(
    mut client: TcpStream,
    mut upstream: TcpStream,
    idle: Duration,
) -> io::Result<()> {
    // Use copy_bidirectional with an overall idle timeout; if either side stalls past idle, we drop.
    let result = timeout(idle, tokio::io::copy_bidirectional(&mut client, &mut upstream)).await;
    match result {
        Ok(Ok((_a, _b))) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout reached")),
    }?;

    // Attempt graceful shutdown
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}
