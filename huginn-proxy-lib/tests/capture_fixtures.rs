//! Fixture capture tests.
//!
//! These tests capture real protocol bytes from reqwest/rustls connections
//! and write them to `benches/fixtures/` for use in micro benchmarks.
//!
//! Run once whenever reqwest or rustls is updated to refresh the fixtures:
//!
//! ```bash
//! cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture
//! ```

//!
//! Commit the resulting `.bin` files in `benches/fixtures/` so that
//! `bench_fingerprinting` uses deterministic, real data.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{
    Backend, FingerprintConfig, KeepAliveConfig, LoggingConfig, Route, SecurityConfig,
    TelemetryConfig, TimeoutConfig,
};
use huginn_proxy_lib::{Config, TlsConfig};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

fn fixtures_dir() -> PathBuf {
    // Resolve relative to the workspace root (two levels up from huginn-proxy-lib/)
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap_or_else(|| panic!("CARGO_MANIFEST_DIR has no parent"))
        .join("benches")
        .join("fixtures")
}

// ---------------------------------------------------------------------------
// Fixture 1: TLS ClientHello bytes from reqwest/rustls
//
// Strategy: start a raw TCP server, accept one connection, read the first
// bytes — those ARE the TLS ClientHello record (before any handshake).
// reqwest will get a connection error but we already have the bytes.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn capture_tls_client_hello() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Spawn raw capture server: read up to 2KB then close
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await?;
        buf.truncate(n);
        Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(buf)
    });

    // Connect with reqwest — TLS handshake will fail (no TLS on the server side)
    // but the ClientHello bytes have already been sent
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(500))
        .build()?
        .get(format!("https://{addr}/"))
        .send()
        .await;

    let bytes = tokio::time::timeout(Duration::from_secs(3), server)
        .await??
        .unwrap_or_default();

    assert!(!bytes.is_empty(), "no bytes captured from TLS ClientHello");

    // Verify it starts with TLS record header (0x16 = handshake)
    assert_eq!(
        bytes[0], 0x16,
        "expected TLS handshake record type 0x16, got 0x{:02x}",
        bytes[0]
    );

    let dir = fixtures_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join("clienthello_reqwest.bin");
    fs::write(&path, &bytes)?;

    println!("Captured {} bytes → {}", bytes.len(), path.display());
    println!("Rust const (for embedding):\nconst CLIENT_HELLO_BYTES: &[u8] = &[");
    for chunk in bytes.chunks(16) {
        let hex: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
        println!("    {},", hex.join(", "));
    }
    println!("];");

    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture 2: HTTP/2 client frames from reqwest/h2 via the proxy
//
// Strategy: start a mock backend that records the forwarded request headers
// (the proxy injects fingerprints there), start the proxy with TLS, make one
// HTTP/2 request, and capture the Akamai fingerprint string.
//
// For the raw HTTP/2 bytes we use CapturingStream which is already exercised
// by the proxy — the Akamai fingerprint string IS the processed output of those
// bytes, so we capture the output value rather than the raw frames.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn capture_fingerprint_values() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::convert::Infallible;
    use std::sync::Mutex;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;

    let captured_ja4: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_akamai: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ja4_clone = Arc::clone(&captured_ja4);
    let akamai_clone = Arc::clone(&captured_akamai);

    // Backend: echo fingerprint headers back as response headers and capture them
    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = backend_listener.accept().await else {
                break;
            };
            let ja4 = Arc::clone(&ja4_clone);
            let akamai = Arc::clone(&akamai_clone);
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let ja4 = Arc::clone(&ja4);
                    let akamai = Arc::clone(&akamai);
                    async move {
                        if let Some(v) = req.headers().get("x-huginn-net-ja4") {
                            *ja4.lock()
                                .unwrap_or_else(|e| panic!("ja4 mutex poisoned: {e}")) =
                                Some(v.to_str().unwrap_or("").to_string());
                        }
                        if let Some(v) = req.headers().get("x-huginn-net-akamai") {
                            *akamai
                                .lock()
                                .unwrap_or_else(|e| panic!("akamai mutex poisoned: {e}")) =
                                Some(v.to_str().unwrap_or("").to_string());
                        }
                        let mut resp = Response::new(Full::new(Bytes::from("ok")));
                        for name in ["x-huginn-net-ja4", "x-huginn-net-akamai"] {
                            if let Some(value) = req.headers().get(name) {
                                resp.headers_mut().insert(
                                    hyper::header::HeaderName::from_bytes(name.as_bytes())
                                        .unwrap_or_else(|e| {
                                            panic!("invalid header name {name}: {e}")
                                        }),
                                    value.clone(),
                                );
                            }
                        }
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Generate TLS cert
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_file = tempfile::NamedTempFile::new()?;
    let key_file = tempfile::NamedTempFile::new()?;
    fs::write(cert_file.path(), cert.pem())?;
    fs::write(key_file.path(), signing_key.serialize_pem())?;

    // Start proxy
    let proxy_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?.port()
    };
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{proxy_port}").parse()?;

    let config = Arc::new(Config {
        listen: proxy_addr,
        backends: vec![Backend { address: backend_addr.to_string(), http_version: None }],
        routes: vec![Route {
            prefix: "/".to_string(),
            backend: backend_addr.to_string(),
            fingerprinting: true,
            force_new_connection: false,
            replace_path: None,
            rate_limit: None,
            headers: None,
        }],
        tls: Some(TlsConfig {
            cert_path: cert_file.path().to_string_lossy().into_owned(),
            key_path: key_file.path().to_string_lossy().into_owned(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            watch_delay_secs: 60,
            options: Default::default(),
            client_auth: Default::default(),
            session_resumption: Default::default(),
        }),
        fingerprint: FingerprintConfig {
            tls_enabled: true,
            http_enabled: true,
            tcp_enabled: false,
            max_capture: 64 * 1024,
        },
        logging: LoggingConfig { level: "warn".to_string(), show_target: false },
        timeout: TimeoutConfig {
            connect_ms: 5000,
            idle_ms: 30_000,
            shutdown_secs: 3,
            tls_handshake_secs: 10,
            connection_handling_secs: 60,
            keep_alive: KeepAliveConfig::default(),
        },
        security: SecurityConfig::default(),
        telemetry: TelemetryConfig { metrics_port: None, otel_log_level: "warn".to_string() },
        headers: None,
        preserve_host: false,
    });

    let proxy_task = tokio::spawn(async move {
        let _ = huginn_proxy_lib::run(config, None, None).await;
    });

    // Wait for proxy ready
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(proxy_addr).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "proxy did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Make one HTTP/2 request to capture Akamai + JA4
    let resp = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(format!("https://{proxy_addr}/capture"))
        .send()
        .await?;

    proxy_task.abort();

    let ja4_val = resp
        .headers()
        .get("x-huginn-net-ja4")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(not present in response — check backend echo)")
        .to_string();

    let akamai_val = resp
        .headers()
        .get("x-huginn-net-akamai")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(not present — HTTP/2 capture may need a second request)")
        .to_string();

    println!("\n--- Captured fingerprint values ---");
    println!("JA4:    {ja4_val}");
    println!("Akamai: {akamai_val}");
    println!("\nPaste into bench_proxy.rs as:");
    println!("const EXPECTED_JA4: &str = \"{ja4_val}\";");
    println!("const EXPECTED_AKAMAI: &str = \"{akamai_val}\";");

    // Write to fixtures dir for reference
    let dir = fixtures_dir();
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("fingerprint_values.txt"),
        format!("JA4={ja4_val}\nAKAMAI={akamai_val}\n"),
    )?;

    println!("\nWritten to {}", dir.join("fingerprint_values.txt").display());

    Ok(())
}
