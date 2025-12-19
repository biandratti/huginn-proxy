#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Backend, Config, LoadBalance};
use crate::tcp::dns::{DnsCache, TargetAddr};
use ahash::RandomState;
use rand::{rng, Rng};
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

pub struct TcpHandler {
    config: Arc<Config>,
    rand_state: RandomState,
    connections_active: Arc<AtomicUsize>,
    connections_total: Arc<AtomicUsize>,
    dns_cache: Arc<DnsCache>,
}

impl TcpHandler {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            rand_state: RandomState::default(),
            connections_active: Arc::new(AtomicUsize::new(0)),
            connections_total: Arc::new(AtomicUsize::new(0)),
            dns_cache: Arc::new(DnsCache::default()),
        }
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
            // connection limit if configured
            if let Some(max) = self.config.max_connections {
                let current = self.connections_active.load(Ordering::Relaxed);
                if current >= max {
                    warn!(%addr, max, "connection limit reached, dropping");
                    continue;
                }
            }
            self.connections_active.fetch_add(1, Ordering::Relaxed);
            self.connections_total.fetch_add(1, Ordering::Relaxed);

            let backend = match self.next_backend(&addr) {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "failed to select backend");
                    self.connections_active.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
            };
            let cfg = self.config.clone();
            let active = self.connections_active.clone();
            let dns = self.dns_cache.clone();
            tokio::spawn(handle_conn(cfg, dns, client, backend, addr, active));
        }
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

async fn handle_conn(
    config: Arc<Config>,
    dns_cache: Arc<DnsCache>,
    client: TcpStream,
    backend: Backend,
    client_addr: std::net::SocketAddr,
    connections_active: Arc<AtomicUsize>,
) {
    let connect_timeout = Duration::from_millis(config.timeouts.connect_ms);

    info!(%client_addr, backend = %backend.address, "accepted connection");

    let target = match TargetAddr::from_str(&backend.address) {
        Ok(t) => t,
        Err(e) => {
            warn!(%client_addr, backend = %backend.address, error = %e, "invalid backend address");
            connections_active.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };

    let destination = match target.resolve_cached(&dns_cache).await {
        Ok(mut addrs) => match addrs.pop() {
            Some(addr) => addr,
            None => {
                warn!(%client_addr, backend = %backend.address, "no resolved addresses");
                connections_active.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        },
        Err(e) => {
            warn!(%client_addr, backend = %backend.address, error = %e, "dns resolve failed");
            connections_active.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };

    let upstream = match timeout(connect_timeout, TcpStream::connect(destination)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(%client_addr, backend = %destination, error = %e, "failed to connect to backend");
            connections_active.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        Err(_) => {
            warn!(%client_addr, backend = %destination, "connect timeout");
            connections_active.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };

    if let Err(e) = bidirectional_copy(client, upstream).await {
        warn!(%client_addr, backend = %backend.address, error = %e, "forwarding ended with error");
    } else {
        info!(%client_addr, backend = %backend.address, "connection closed");
    }
    connections_active.fetch_sub(1, Ordering::Relaxed);
}

async fn bidirectional_copy(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    // Simple duplex copy; relies on peer close or error to finish.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;

    // Attempt graceful shutdown
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}
