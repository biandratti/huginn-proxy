#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Backend, Config, LoadBalance};
use crate::tcp::dns::{DnsCache, TargetAddr};
use crate::tcp::fingerprint::HDR_HUGINN_NET_TLS;
use crate::tcp::http_peek::{peek_request_line, replay_buffered, PeekOutcome};
use crate::tcp::metrics::ConnectionCount;
use crate::tcp::tls::ClientStream;
use ahash::RandomState;
use huginn_net_tls::tls_process::{is_tls_traffic, parse_tls_client_hello};
use rand::{rng, Rng};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
type BoxedIo = Box<dyn IoStream>;

pub struct TcpHandler {
    config: Arc<Config>,
    rand_state: RandomState,
    connections: Arc<ConnectionCount>,
    dns_cache: Arc<DnsCache>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
}

impl TcpHandler {
    pub fn new(
        config: Arc<Config>,
        connections: Arc<ConnectionCount>,
        tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    ) -> Self {
        Self {
            config,
            rand_state: RandomState::default(),
            connections,
            dns_cache: Arc::new(DnsCache::default()),
            tls_acceptor,
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
            let tls = self.tls_acceptor.clone();
            tokio::spawn(async move {
                let client_stream = if let Some(acceptor) = tls {
                    let stream = client;
                    let mut buf = [0u8; 4096];
                    let tls_fp = if cfg.fingerprint.tls_enabled {
                        match stream.peek(&mut buf).await {
                            Ok(n) if n > 0 && is_tls_traffic(&buf[..n]) => {
                                parse_tls_client_hello(&buf[..n])
                                    .ok()
                                    .map(|sig| sig.generate_ja4().full.value().to_string())
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    match acceptor.accept(stream).await {
                        Ok(s) => ClientStream::Tls(Box::new(s), tls_fp),
                        Err(e) => {
                            let snapshot = counts.snapshot();
                            warn!(%addr, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "tls handshake failed");
                            counts.increment_errors();
                            counts.decrement();
                            return;
                        }
                    }
                } else {
                    ClientStream::Plain(client)
                };
                handle_conn(cfg, dns, client_stream, backend, addr, counts).await;
            });
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
    client: ClientStream,
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

    let (mut client, tls_fp) = match client {
        ClientStream::Plain(s) => (Box::new(s) as BoxedIo, None),
        ClientStream::Tls(s, fp) => (Box::new(s) as BoxedIo, fp),
    };
    let mut initial_buf = Vec::new();
    let mut selected_backend_addr = destination;
    let max_peek = config.http.max_peek_bytes;
    if config.peek_http {
        match peek_request_line(&mut client, max_peek).await {
            Ok(PeekOutcome::Http(mut peeked)) => {
                if let Some(fp) = tls_fp {
                    if let Some(delim_start) =
                        peeked.buffered.windows(4).rposition(|w| w == b"\r\n\r\n")
                    {
                        let header = format!("\r\n{HDR_HUGINN_NET_TLS}: {fp}\r\n");
                        let cap = peeked.buffered.len().saturating_add(header.len());
                        let mut with_fp = Vec::with_capacity(cap);
                        with_fp.extend_from_slice(&peeked.buffered[..delim_start]);
                        with_fp.extend_from_slice(header.as_bytes());
                        with_fp.extend_from_slice(&peeked.buffered[delim_start..]);
                        peeked.buffered = with_fp;
                    }
                }
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
        if let Err(e) = bidirectional_copy(&mut client, &mut upstream).await {
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

    let mut upstream = upstream;
    if let Err(e) = bidirectional_copy(&mut client, &mut upstream).await {
        let snapshot = connections.snapshot();
        warn!(%client_addr, backend = %backend.address, error = %e, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "forwarding ended with error");
        connections.increment_errors();
    } else {
        let snapshot = connections.snapshot();
        info!(%client_addr, backend = %backend.address, current = snapshot.current, total = snapshot.total, errors = snapshot.errors, "connection closed");
    }
    connections.decrement();
}

async fn bidirectional_copy<C, U>(client: &mut C, upstream: &mut U) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    // Simple duplex copy; relies on peer close or error to finish.
    tokio::io::copy_bidirectional(client, upstream).await?;

    // Attempt graceful shutdown
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}
