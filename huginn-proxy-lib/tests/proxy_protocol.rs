//! E2E: PROXY protocol v2.
//!
//! Drives the full accept loop (in-process proxy + mock backend over plain HTTP) and asserts that
//! a v2 header from a **trusted** peer makes the proxy recover the client's `(src_ip, src_port)`
//! and reflect it in `X-Forwarded-For` / `X-Forwarded-Port`. Also covers auto-detection (no header
//! → direct client) and the `require` + untrusted-peer drop.
//!
//! The TLS test (`tls_proxy_header_before_clienthello`) proves end-to-end byte alignment in a live
//! TLS handshake: the PROXY v2 header is written to the raw TCP stream, then `tokio-rustls`
//! performs the TLS handshake over the same stream. The parser must consume exactly the header
//! bytes so that the very next byte huginn reads is the TLS `0x16 0x03` record.

use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::config::{
    Backend, Domain, FingerprintConfig, KeepAliveConfig, ListenConfig, LoggingConfig,
    ProxyProtocolConfig, ProxyProtocolMode, Route, SecurityConfig, TelemetryConfig, TimeoutConfig,
};
use huginn_proxy_lib::{Config, Metrics, TlsConfig, WatchOptions};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

/// 12-byte PROXY v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
const V2_SIGNATURE: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// Build a PROXY protocol v2 header for an IPv4 TCP `(src, dst)` pair.
fn proxy_v2_ipv4(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
    let mut buf = Vec::with_capacity(28);
    buf.extend_from_slice(&V2_SIGNATURE);
    buf.push((2 << 4) | 0x1); // version 2, command PROXY
    buf.push((0x1 << 4) | 0x1); // AF_INET, STREAM
    buf.extend_from_slice(&12u16.to_be_bytes()); // address block length
    buf.extend_from_slice(&src.ip().octets());
    buf.extend_from_slice(&dst.ip().octets());
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(&dst.port().to_be_bytes());
    buf
}

/// Build a PROXY protocol v2 header for an IPv6 TCP `(src, dst)` pair (AF_INET6, 36-byte block).
fn proxy_v2_ipv6(src_ip: Ipv6Addr, src_port: u16, dst_ip: Ipv6Addr, dst_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&V2_SIGNATURE);
    buf.push((2 << 4) | 0x1); // version 2, command PROXY
    buf.push((0x2 << 4) | 0x1); // AF_INET6, STREAM
    buf.extend_from_slice(&36u16.to_be_bytes()); // address block length
    buf.extend_from_slice(&src_ip.octets());
    buf.extend_from_slice(&dst_ip.octets());
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf
}

/// Backend that echoes the `X-Forwarded-For` / `X-Forwarded-Port` it received into the body.
async fn spawn_echo_backend(
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc =
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| async move {
                        let xff = req
                            .headers()
                            .get("x-forwarded-for")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("(none)")
                            .to_string();
                        let xfp = req
                            .headers()
                            .get("x-forwarded-port")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("(none)")
                            .to_string();
                        let body = format!("xff={xff};xfp={xfp}");
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    Ok((addr, handle.abort_handle()))
}

fn free_port() -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Spawn the proxy from a TOML config and wait until it accepts connections.
async fn spawn_proxy(
    toml: &str,
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    std::fs::write(tmp.path(), toml)?;

    let config = load_from_path(tmp.path())?;
    let listen_addr = config.listen.addrs[0];

    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let dynamic_cfg = Arc::new(ArcSwap::from_pointee(dynamic_cfg));

    let handle = tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            static_cfg,
            dynamic_cfg,
            Metrics::new_noop(),
            None,
            WatchOptions::default(),
            shutdown_tx,
            huginn_proxy_lib::Readiness::new(),
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(listen_addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("proxy at {listen_addr} did not become ready"))?;

    // `tmp` must outlive the proxy task (it reads the file at startup); leak it so the file stays.
    std::mem::forget(tmp);
    Ok((listen_addr, handle.abort_handle()))
}

/// Open a raw connection, optionally prepend `header_prefix`, send one plain HTTP/1.1 request,
/// and return the full response text (empty string if the peer dropped us without replying).
async fn raw_request(proxy: SocketAddr, header_prefix: &[u8]) -> String {
    let mut stream = match TcpStream::connect(proxy).await {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    if !header_prefix.is_empty() && stream.write_all(header_prefix).await.is_err() {
        return String::new();
    }
    let req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    // A dropped connection surfaces as either EOF (empty) or a reset error; both mean "no reply".
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn config_toml(listen_port: u16, backend: SocketAddr, mode: &str, trusted: &str) -> String {
    format!(
        r#"listen = {{ addrs = ["127.0.0.1:{listen_port}"], proxy_protocol = {{ mode = "{mode}" }} }}
backends = [{{ address = "{backend}" }}]

[security.trusted_proxies]
cidrs = [{trusted}]

[[domains]]
host = "127.0.0.1"
routes = [{{ prefix = "/", backend = "{backend}" }}]
"#
    )
}

#[tokio::test]
async fn optional_trusted_peer_header_is_applied() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "optional", "\"127.0.0.1/32\", \"::1/128\""))
            .await?;

    let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51115);
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let header = proxy_v2_ipv4(src, dst);

    let resp = raw_request(proxy, &header).await;

    assert!(resp.contains("200"), "expected a 200 response, got: {resp}");
    assert!(
        resp.contains("xff=203.0.113.7"),
        "X-Forwarded-For should be the PROXY-declared client IP, got: {resp}"
    );
    assert!(
        resp.contains("xfp=51115"),
        "X-Forwarded-Port should be the PROXY-declared source port, got: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn ipv4_mapped_client_is_normalized_in_forwarded_headers() -> TestResult {
    // A downstream LB declares the client as an IPv4-mapped IPv6 address (`::ffff:203.0.113.7`).
    // The handler must normalize it to plain IPv4 before building X-Forwarded-For (same as the
    // ip_filter / rate-limit key), so the backend sees `203.0.113.7`, not `::ffff:203.0.113.7`.
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "optional", "\"127.0.0.1/32\", \"::1/128\""))
            .await?;

    let src_v4 = Ipv4Addr::new(203, 0, 113, 7);
    let header = proxy_v2_ipv6(
        src_v4.to_ipv6_mapped(),
        51115,
        Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(),
        port,
    );

    let resp = raw_request(proxy, &header).await;

    assert!(resp.contains("200"), "expected a 200 response, got: {resp}");
    assert!(
        resp.contains("xff=203.0.113.7"),
        "IPv4-mapped client must be normalized to plain IPv4 in X-Forwarded-For, got: {resp}"
    );
    assert!(
        !resp.contains("::ffff:"),
        "X-Forwarded-For must not carry the IPv4-mapped form, got: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn optional_no_header_is_direct_client() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "optional", "\"127.0.0.1/32\"")).await?;

    // No PROXY header: auto-detection must leave the stream intact and treat us as a direct client.
    let resp = raw_request(proxy, &[]).await;

    assert!(resp.contains("200"), "expected a 200 response, got: {resp}");
    assert!(
        resp.contains("xff=127.0.0.1"),
        "without a header the client IP is the loopback socket peer, got: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn require_untrusted_peer_is_dropped() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    // Trust only a non-loopback range, so the loopback test client is untrusted.
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "require", "\"192.0.2.0/24\"")).await?;

    let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51115);
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let header = proxy_v2_ipv4(src, dst);

    let resp = raw_request(proxy, &header).await;

    assert!(
        !resp.contains("200"),
        "require + untrusted peer must be dropped with no HTTP response, got: {resp}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS end-to-end: PROXY v2 header → TLS ClientHello → HTTP/1.1
// ---------------------------------------------------------------------------

/// Spawn the proxy with TLS termination enabled.
///
/// Returns the listen address, the raw DER cert bytes (so the test client can
/// build a `RootCertStore` that trusts it), and an abort handle.
async fn spawn_proxy_tls(
    backend: SocketAddr,
    proxy_protocol_mode: ProxyProtocolMode,
    trusted_cidr: &str,
) -> Result<(SocketAddr, Vec<u8>, tokio::task::AbortHandle), BoxError> {
    // Install the process-level rustls CryptoProvider once.
    static CRYPTO_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    CRYPTO_INIT.get_or_init(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    // Generate a self-signed cert for "localhost".
    // IP addresses are not valid SNI values in TLS; rustls omits SNI when connecting by IP,
    // so the cert resolver on the server side never finds the domain. Use a DNS hostname.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der_bytes = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    // Write cert + key to temp files (proxy reads from disk).
    let cert_file = tempfile::Builder::new().suffix(".crt").tempfile()?;
    let key_file = tempfile::Builder::new().suffix(".key").tempfile()?;
    std::fs::write(cert_file.path(), &cert_pem)?;
    std::fs::write(key_file.path(), &key_pem)?;

    // Parse trusted_proxies from a CIDR string.
    let trusted_proxies = huginn_proxy_lib::config::TrustedProxiesConfig {
        cidrs: if trusted_cidr.is_empty() {
            vec![]
        } else {
            vec![trusted_cidr.parse()?]
        },
        insecure: false,
    };

    let listen_port = free_port()?;
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;

    let config = Config {
        listen: ListenConfig {
            addrs: vec![listen_addr],
            proxy_protocol: ProxyProtocolConfig { mode: proxy_protocol_mode, ..Default::default() },
            ..Default::default()
        },
        backends: vec![Backend {
            address: backend.to_string(),
            http_version: None,
            health_check: None,
        }],
        domains: vec![Domain {
            host: Some("localhost".to_string()),
            cert_path: Some(cert_file.path().to_string_lossy().into_owned()),
            key_path: Some(key_file.path().to_string_lossy().into_owned()),
            headers: None,
            security: None,
            fingerprinting: None,
            routes: vec![Route {
                prefix: "/".to_string(),
                backend: backend.to_string(),
                fingerprinting: None,
                force_new_connection: false,
                replace_path: None,
                security: None,
                headers: None,
            }],
        }],
        tls: Some(TlsConfig {
            alpn: vec!["http/1.1".to_string()],
            options: Default::default(),
            client_auth: Default::default(),
            session_resumption: Default::default(),
        }),
        fingerprint: FingerprintConfig {
            tls_enabled: false,
            http_enabled: false,
            tcp_enabled: false,
            max_capture: 0,
        },
        logging: LoggingConfig { level: "error".to_string(), show_target: false },
        timeout: TimeoutConfig {
            upstream_connect_ms: Some(5000),
            proxy_idle_ms: 30_000,
            shutdown_secs: 3,
            tls_handshake_secs: 10,
            connection_handling_secs: 60,
            keep_alive: KeepAliveConfig::default(),
        },
        security: SecurityConfig { trusted_proxies, ..Default::default() },
        telemetry: TelemetryConfig { metrics_port: None, otel_log_level: "error".to_string() },
        reload: huginn_proxy_lib::config::ReloadConfig::default(),
        headers: None,
        preserve_host: false,
        backend_pool: Default::default(),
    };

    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let dynamic_cfg = Arc::new(ArcSwap::from_pointee(dynamic_cfg));

    let handle = tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            static_cfg,
            dynamic_cfg,
            Metrics::new_noop(),
            None,
            WatchOptions::default(),
            shutdown_tx,
            huginn_proxy_lib::Readiness::new(),
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(listen_addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("TLS proxy at {listen_addr} did not become ready"))?;

    // Keep temp files alive for the duration of the proxy task.
    std::mem::forget(cert_file);
    std::mem::forget(key_file);

    Ok((listen_addr, cert_der_bytes, handle.abort_handle()))
}

/// Open a raw TCP stream, write `proxy_header`, then perform a TLS handshake (trusting
/// `server_cert_der`). On success returns the stream ready for HTTP traffic.
async fn connect_tls_after_proxy_header(
    proxy: SocketAddr,
    proxy_header: &[u8],
    server_cert_der: &[u8],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(tokio_rustls::rustls::pki_types::CertificateDer::from(server_cert_der.to_vec()))?;

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")?;

    let mut tcp = TcpStream::connect(proxy).await?;
    // Write PROXY v2 header *before* TLS ClientHello.
    tcp.write_all(proxy_header).await?;

    let tls = connector.connect(server_name, tcp).await?;
    Ok(tls)
}

/// PROXY v2 header + TLS handshake + HTTP/1.1 GET.
///
/// Proves byte alignment: the parser consumes exactly the 28-byte v2 header so
/// that huginn reads the TLS `0x16 0x03` ClientHello record as the first byte.
#[tokio::test]
async fn tls_proxy_header_before_clienthello() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let (proxy, cert_der, _ph) =
        spawn_proxy_tls(backend, ProxyProtocolMode::Optional, "127.0.0.1/32").await?;

    let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 54321);
    let dst_port = proxy.port();
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), dst_port);
    let header = proxy_v2_ipv4(src, dst);

    let mut tls_stream = connect_tls_after_proxy_header(proxy, &header, &cert_der).await?;

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_stream.write_all(request).await?;

    let mut buf = Vec::new();
    tls_stream.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);

    assert!(resp.contains("200"), "expected a 200 response over TLS, got: {resp}");
    assert!(
        resp.contains("xff=203.0.113.99"),
        "X-Forwarded-For should be the PROXY-declared client IP, got: {resp}"
    );
    assert!(
        resp.contains("xfp=54321"),
        "X-Forwarded-Port should be the PROXY-declared source port, got: {resp}"
    );
    Ok(())
}
