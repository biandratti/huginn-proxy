//! Dual-listen HTTP→HTTPS redirect through the accept loop.

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::{Metrics, WatchOptions};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

fn free_port() -> Result<u16, BoxError> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

fn write_pem_pair() -> Result<(tempfile::NamedTempFile, tempfile::NamedTempFile), BoxError> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_file = tempfile::NamedTempFile::new()?;
    let key_file = tempfile::NamedTempFile::new()?;
    fs::write(cert_file.path(), cert.pem())?;
    fs::write(key_file.path(), signing_key.serialize_pem())?;
    Ok((cert_file, key_file))
}

struct RedirectProxy {
    http: SocketAddr,
    https_port: u16,
    _config: tempfile::NamedTempFile,
    _cert: tempfile::NamedTempFile,
    _key: tempfile::NamedTempFile,
    _ca: Option<tempfile::NamedTempFile>,
}

async fn spawn_redirect_proxy(
    host_line: &str,
    extra_domain: &str,
    https_redirection: bool,
    with_client_ca: bool,
) -> Result<RedirectProxy, BoxError> {
    let (cert, key) = write_pem_pair()?;
    let ca = if with_client_ca {
        let rcgen::CertifiedKey { cert: ca_cert, .. } =
            rcgen::generate_simple_self_signed(vec!["client-ca".to_string()])?;
        let ca_file = tempfile::NamedTempFile::new()?;
        fs::write(ca_file.path(), ca_cert.pem())?;
        Some(ca_file)
    } else {
        None
    };
    let http_port = free_port()?;
    let https_port = free_port()?;
    let client_ca_line = ca.as_ref().map_or(String::new(), |ca_file| {
        format!("client_ca_path = \"{}\"", ca_file.path().display())
    });
    // `routes` must stay in the `[[domains]]` table. Extra `[domains.security.*]` tables
    // come after, or TOML would parse `routes` as a field of the nested security table.
    let toml = format!(
        r#"
listen = {{ port = {http_port}, port_tls = {https_port}, address_v4 = ["127.0.0.1"], https_redirection = {https_redirection} }}
backends = [{{ address = "127.0.0.1:1" }}]

[[domains]]
{host_line}
cert_path = "{cert}"
key_path = "{key}"
{client_ca_line}
routes = [{{ prefix = "/", backend = "127.0.0.1:1" }}]
{extra_domain}
"#,
        cert = cert.path().display(),
        key = key.path().display(),
    );
    let config_file = tempfile::Builder::new().suffix(".toml").tempfile()?;
    fs::write(config_file.path(), toml)?;
    let config = load_from_path(config_file.path())?;
    let http_addr = config
        .listen
        .sockets()?
        .into_iter()
        .find(|s| !s.tls_enabled)
        .ok_or("missing HTTP socket")?
        .addr;
    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            Arc::new(static_cfg),
            Arc::new(ArcSwap::from_pointee(dynamic_cfg)),
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
            if TcpStream::connect(http_addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("proxy at {http_addr} did not become ready"))?;
    Ok(RedirectProxy {
        http: http_addr,
        https_port,
        _config: config_file,
        _cert: cert,
        _key: key,
        _ca: ca,
    })
}

async fn raw_http(addr: SocketAddr, request: &str) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn get(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

fn location_url(host: &str, path: &str, tls_port: u16) -> String {
    format!("https://{host}:{tls_port}{path}")
}

fn has_location(response: &str, url: &str) -> bool {
    response
        .to_ascii_lowercase()
        .contains(&format!("location: {url}").to_ascii_lowercase())
}

#[tokio::test]
async fn unmatched_host_is_421_not_301() -> TestResult {
    let proxy = spawn_redirect_proxy("host = \"api.example.com\"", "", true, false).await?;
    let response = raw_http(proxy.http, &get("other.com", "/path")).await?;
    assert!(response.contains("421"), "expected 421, got: {response}");
    assert!(
        !response.to_ascii_lowercase().contains("location:"),
        "unmatched host must not advertise HTTPS: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn catch_all_redirects_with_request_host() -> TestResult {
    let proxy = spawn_redirect_proxy("", "", true, false).await?;
    let response = raw_http(proxy.http, &get("other.com", "/v1?q=1")).await?;
    assert!(response.contains("301"), "expected 301, got: {response}");
    let expected = location_url("other.com", "/v1?q=1", proxy.https_port);
    assert!(
        has_location(&response, &expected),
        "catch-all Location must use the request host, expected {expected}, got: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn empty_host_on_catch_all_is_400_without_location() -> TestResult {
    let proxy = spawn_redirect_proxy("", "", true, false).await?;
    let response = raw_http(proxy.http, "GET / HTTP/1.0\r\n\r\n").await?;
    assert!(response.contains("400"), "expected 400, got: {response}");
    assert!(
        !response.to_ascii_lowercase().contains("location:"),
        "empty host must not emit Location: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn ip_filter_denies_before_redirect() -> TestResult {
    let proxy = spawn_redirect_proxy(
        "host = \"api.example.com\"",
        r#"[domains.security.ip_filter]
mode = "denylist"
denylist = ["127.0.0.1/32"]"#,
        true,
        false,
    )
    .await?;
    let response = raw_http(proxy.http, &get("api.example.com", "/")).await?;
    assert!(response.contains("403"), "expected 403, got: {response}");
    assert!(!response.contains("301"), "blocked client must not see a redirect: {response}");
    Ok(())
}

#[tokio::test]
async fn redirect_does_not_consume_rate_limit() -> TestResult {
    let proxy = spawn_redirect_proxy(
        "host = \"api.example.com\"",
        r#"[domains.security.rate_limit]
enabled = true
burst = 1
window_seconds = 60"#,
        true,
        false,
    )
    .await?;
    for _ in 0..2 {
        let response = raw_http(proxy.http, &get("api.example.com", "/")).await?;
        assert!(
            response.contains("301"),
            "redirect must not consume the rate-limit budget: {response}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn mtls_plaintext_redirects_when_enabled() -> TestResult {
    let proxy = spawn_redirect_proxy("host = \"api.example.com\"", "", true, true).await?;
    let response = raw_http(proxy.http, &get("api.example.com", "/secure")).await?;
    assert!(response.contains("301"), "expected 301, got: {response}");
    let expected = location_url("api.example.com", "/secure", proxy.https_port);
    assert!(
        has_location(&response, &expected),
        "mTLS plaintext with redirect must 301, expected {expected}, got: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn mtls_plaintext_is_421_when_redirect_disabled() -> TestResult {
    let proxy = spawn_redirect_proxy("host = \"api.example.com\"", "", false, true).await?;
    let response = raw_http(proxy.http, &get("api.example.com", "/secure")).await?;
    assert!(response.contains("421"), "expected 421, got: {response}");
    assert!(
        !response.contains("301"),
        "mTLS plaintext with redirect off must not 301: {response}"
    );
    Ok(())
}
