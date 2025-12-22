#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Backend, Config, LoadBalance};
use crate::tcp::dns::{DnsCache, TargetAddr};
use crate::tcp::http_peek::{peek_request_line, replay_buffered, PeekOutcome};
use crate::tcp::metrics::ConnectionCount;
use ahash::RandomState;
use rand::{rng, Rng};
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

pub struct TcpHandler {
    config: Arc<Config>,
    rand_state: RandomState,
    connections: Arc<ConnectionCount>,
    dns_cache: Arc<DnsCache>,
}

impl TcpHandler {
    pub fn new(config: Arc<Config>, connections: Arc<ConnectionCount>) -> Self {
        Self {
            config,
            rand_state: RandomState::default(),
            connections,
            dns_cache: Arc::new(DnsCache::default()),
        }
    }

    pub async fn run(
        &self,
        listener: TcpListener,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), String> {
        loop {
            let accept_fut = listener.accept();
            let result = tokio::select! {
                res = accept_fut => res,
                res = shutdown.changed() => {
                    if res.is_ok() {
                        info!("shutdown signal received, stopping accept loop");
                        break;
                    } else {
                        // sender dropped; treat as no shutdown signal
                        continue;
                    }
                }
            };
            let (client, addr) = match result {
                Ok(pair) => pair,
                Err(e) => {
                    let snapshot = self.connections.snapshot();
                    warn!(error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "failed to accept connection");
                    continue;
                }
            };
            // connection limit if configured
            if let Some(max) = self.config.max_connections {
                let current = self.connections.current();
                if current >= max {
                    warn!(%addr, max, "connection limit reached, dropping");
                    continue;
                }
            }
            self.connections.increment();
            let snapshot = self.connections.snapshot();
            info!(%addr, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "accepted connection");

            let backend = match self.next_backend(&addr) {
                Ok(b) => b,
                Err(e) => {
                    let snapshot = self.connections.snapshot();
                    warn!(error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "failed to select backend");
                    self.connections.decrement();
                    continue;
                }
            };
            let cfg = self.config.clone();
            let counts = self.connections.clone();
            let dns = self.dns_cache.clone();
            tokio::spawn(handle_conn(cfg, dns, client, backend, addr, counts));
        }
        Ok(())
    }

    fn next_backend(&self, client_addr: &SocketAddr) -> Result<Backend, String> {
        let len = self.config.backends.len();
        if len == 0 {
            return Err("no backends configured".into());
        }

        let len_usize = len;
        let idx = match self.config.balancing {
            LoadBalance::None => 0,
            LoadBalance::SourceIp => {
                let hash = self.rand_state.hash_one(client_addr.ip());
                (hash as usize).checked_rem(len_usize).unwrap_or_default()
            }
            LoadBalance::SourceSocket => {
                let hash = self.rand_state.hash_one(client_addr);
                (hash as usize).checked_rem(len_usize).unwrap_or_default()
            }
            LoadBalance::Random => rng().random_range(0..len),
        };

        self.config
            .backends
            .get(idx)
            .cloned()
            .ok_or_else(|| "backend index out of range".to_string())
    }
}

fn select_route<'a>(
    path: &str,
    http_cfg: &'a crate::config::types::HttpConfig,
) -> Option<&'a crate::config::types::HttpRoute> {
    http_cfg
        .routes
        .iter()
        .max_by_key(|r| {
            if path.starts_with(&r.prefix) {
                r.prefix.len()
            } else {
                0
            }
        })
        .filter(|r| path.starts_with(&r.prefix))
}
async fn handle_conn(
    config: Arc<Config>,
    dns_cache: Arc<DnsCache>,
    client: TcpStream,
    backend: Backend,
    client_addr: std::net::SocketAddr,
    connections: Arc<ConnectionCount>,
) {
    let connect_timeout = Duration::from_millis(config.timeouts.connect_ms);

    info!(%client_addr, backend = %backend.address, "accepted connection");

    let target = match TargetAddr::from_str(&backend.address) {
        Ok(t) => t,
        Err(e) => {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "invalid backend address");
            connections.increment_errors();
            connections.decrement();
            return;
        }
    };

    let destination = match target.resolve_cached(&dns_cache).await {
        Ok(mut addrs) => match addrs.pop() {
            Some(addr) => addr,
            None => {
                let snapshot = connections.snapshot();
                warn!(%client_addr, backend = %backend.address, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "no resolved addresses");
                connections.increment_errors();
                connections.decrement();
                return;
            }
        },
        Err(e) => {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "dns resolve failed");
            connections.increment_errors();
            connections.decrement();
            return;
        }
    };

    // Optional HTTP peek
    let mut client = client;
    let mut initial_buf = Vec::new();
    let mut selected_backend_addr = destination;
    let max_peek = config.http.max_peek_bytes;
    if config.peek_http || !config.http.routes.is_empty() {
        match peek_request_line(&mut client, max_peek).await {
            Ok(PeekOutcome::Http(peeked)) => {
                initial_buf = peeked.buffered.clone();
                if let Some(route) = select_route(&peeked.path, &config.http) {
                    // resolve routed backend
                    if let Ok(t) = TargetAddr::from_str(&route.backend) {
                        if let Ok(mut addrs) = t.resolve_cached(&dns_cache).await {
                            if let Some(addr) = addrs.pop() {
                                selected_backend_addr = addr;
                            }
                        }
                    }
                }
            }
            Ok(PeekOutcome::NotHttp(buf)) => {
                initial_buf = buf;
            }
            Err(e) => {
                let snapshot = connections.snapshot();
                warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "peek failed");
            }
        }
    }

    let upstream = match timeout(connect_timeout, TcpStream::connect(selected_backend_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %selected_backend_addr, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "failed to connect to backend");
            connections.increment_errors();
            connections.decrement();
            return;
        }
        Err(_) => {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %selected_backend_addr, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "connect timeout");
            connections.increment_errors();
            connections.decrement();
            return;
        }
    };

    // Replay buffered data if any (HTTP peek)
    if !initial_buf.is_empty() {
        let mut upstream = upstream;
        if let Err(e) = replay_buffered(&mut upstream, &initial_buf).await {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %selected_backend_addr, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "failed to replay buffered data");
            connections.increment_errors();
            connections.decrement();
            return;
        }
        if let Err(e) = bidirectional_copy(client, upstream).await {
            let snapshot = connections.snapshot();
            warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "forwarding ended with error");
            connections.increment_errors();
        } else {
            let snapshot = connections.snapshot();
            info!(%client_addr, backend = %backend.address, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "connection closed");
        }
        connections.decrement();
        return;
    }

    if let Err(e) = bidirectional_copy(client, upstream).await {
        let snapshot = connections.snapshot();
        warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "forwarding ended with error");
        connections.increment_errors();
    } else {
        let snapshot = connections.snapshot();
        info!(%client_addr, backend = %backend.address, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "connection closed");
    }
    connections.decrement();
}

async fn bidirectional_copy(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    // Simple duplex copy; relies on peer close or error to finish.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;

    // Attempt graceful shutdown
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}
