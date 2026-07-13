//! Unit-level tests for `resolve_peer`.
//!
//! Each test establishes a real loopback TCP connection (so `TcpStream::peek` works correctly)
//! and verifies the peer-resolution logic across the three `ProxyProtocolMode` variants and
//! the trusted / untrusted split.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use huginn_proxy_lib::config::ProxyProtocolMode;
use huginn_proxy_lib::proxy::accept::resolve_peer;
use huginn_proxy_lib::telemetry::Metrics;
use ipnet::IpNet;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Bind a listener on localhost, spawn a client that connects and sends `data`,
/// then return the server-side `TcpStream` and the client's `SocketAddr`.
///
/// The client task keeps the connection open for 200 ms so the server can consume
/// any headers before the peer closes.
async fn accept_one(
    data: &'static [u8],
) -> Result<(TcpStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await?;
        if !data.is_empty() {
            s.write_all(data).await?;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (stream, peer) = listener.accept().await?;
    Ok((stream, peer))
}

fn localhost_net() -> Result<IpNet, <IpNet as FromStr>::Err> {
    IpNet::from_str("127.0.0.1/32")
}

/// Off mode: returns `socket_peer` immediately, no stream I/O.
#[tokio::test]
async fn resolve_peer_off_passthrough() -> TestResult {
    let (mut stream, socket_peer) = accept_one(b"").await?;
    let metrics = Metrics::new_noop();

    let result = resolve_peer(
        ProxyProtocolMode::Off,
        Duration::from_secs(5),
        &metrics,
        &[],
        &mut stream,
        socket_peer,
    )
    .await;

    assert_eq!(result, Some(socket_peer));
    Ok(())
}

/// Optional mode, untrusted peer (no trusted_proxies): passes the socket peer through
/// without parsing any PROXY header.
#[tokio::test]
async fn resolve_peer_optional_untrusted_passthrough() -> TestResult {
    let (mut stream, socket_peer) = accept_one(b"").await?;
    let metrics = Metrics::new_noop();

    let result = resolve_peer(
        ProxyProtocolMode::Optional,
        Duration::from_secs(5),
        &metrics,
        &[], // no trusted proxies → untrusted
        &mut stream,
        socket_peer,
    )
    .await;

    assert_eq!(result, Some(socket_peer));
    Ok(())
}

/// Require mode, untrusted peer: connection must be dropped.
#[tokio::test]
async fn resolve_peer_require_untrusted_drops() -> TestResult {
    let (mut stream, socket_peer) = accept_one(b"").await?;
    let metrics = Metrics::new_noop();

    let result = resolve_peer(
        ProxyProtocolMode::Require,
        Duration::from_secs(5),
        &metrics,
        &[], // no trusted proxies → untrusted
        &mut stream,
        socket_peer,
    )
    .await;

    assert_eq!(result, None);
    Ok(())
}

/// Optional mode, trusted peer, bytes that are not a PROXY header (TLS record type byte):
/// `detect_proxy_protocol` resolves to `None` and the peer passes through as-is.
#[tokio::test]
async fn resolve_peer_optional_trusted_no_header_passthrough() -> TestResult {
    // 0x16 = TLS record type; neither v1 prefix ('P') nor v2 signature (0x0D).
    let (mut stream, socket_peer) = accept_one(b"\x16\x03\x01").await?;
    let metrics = Metrics::new_noop();
    let trusted = [localhost_net()?];

    let result = resolve_peer(
        ProxyProtocolMode::Optional,
        Duration::from_secs(5),
        &metrics,
        &trusted,
        &mut stream,
        socket_peer,
    )
    .await;

    assert_eq!(result, Some(socket_peer));
    Ok(())
}

/// Optional mode, trusted peer, valid PROXY v1 header: the declared client address is
/// recovered from the header and returned instead of the socket peer.
#[tokio::test]
async fn resolve_peer_optional_trusted_v1_header_recovers_client() -> TestResult {
    let header = b"PROXY TCP4 192.168.1.1 10.0.0.2 12345 80\r\n";
    let (mut stream, socket_peer) = accept_one(header).await?;
    let metrics = Metrics::new_noop();
    let trusted = [localhost_net()?];

    let result = resolve_peer(
        ProxyProtocolMode::Optional,
        Duration::from_secs(5),
        &metrics,
        &trusted,
        &mut stream,
        socket_peer,
    )
    .await;

    let expected: SocketAddr = SocketAddr::new(IpAddr::from_str("192.168.1.1")?, 12345);
    assert_eq!(result, Some(expected));
    Ok(())
}
