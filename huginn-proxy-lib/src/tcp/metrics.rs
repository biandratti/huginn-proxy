#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[derive(Debug, Default)]
pub struct ConnectionCount {
    current: AtomicUsize,
    total: AtomicUsize,
    errors: AtomicUsize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionSnapshot {
    pub current: usize,
    pub total: usize,
    pub errors: usize,
}

impl ConnectionCount {
    pub fn increment(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.current
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .ok();
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn errors(&self) -> usize {
        self.errors.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot { current: self.current(), total: self.total(), errors: self.errors() }
    }

    /// Render counters in Prometheus exposition text format.
    #[allow(dead_code)]
    pub fn to_prometheus(&self, prefix: &str) -> String {
        let snap = self.snapshot();
        format!(
            "# HELP {p}_connections_active Active TCP connections\n\
             # TYPE {p}_connections_active gauge\n\
             {p}_connections_active {active}\n\
             # HELP {p}_connections_total Total TCP connections accepted\n\
             # TYPE {p}_connections_total counter\n\
             {p}_connections_total {total}\n\
             # HELP {p}_connections_errors_total Total TCP connection errors\n\
             # TYPE {p}_connections_errors_total counter\n\
             {p}_connections_errors_total {errors}\n",
            p = prefix,
            active = snap.current,
            total = snap.total,
            errors = snap.errors
        )
    }
}

pub async fn serve_prometheus_metrics(
    addr: SocketAddr,
    counters: Arc<ConnectionCount>,
    prefix: &str,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let body = counters.to_prometheus(prefix);
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::spawn(async move {
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
