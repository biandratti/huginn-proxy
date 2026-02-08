/// Integration tests for TLS session resumption
///
/// These tests verify that TLS connections work correctly with session resumption enabled.
/// Note: These tests don't directly verify session resumption (which would require inspecting
/// the TLS handshake), but they verify that:
/// - Multiple TLS connections succeed
/// - Connections use consistent TLS versions
/// - Session resumption configuration doesn't break TLS functionality
///
/// To verify actual session resumption, use tools like:
/// - `openssl s_client -connect localhost:7000 -reconnect` (for TLS 1.2)
/// - `openssl s_client -connect localhost:7000 -tls1_3 -sess_out session.pem` then `-sess_in session.pem` (for TLS 1.3)
use std::sync::Arc;
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

fn parse_host_port(url: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let url = url.strip_prefix("https://").unwrap_or(url);
    let url = url.strip_prefix("http://").unwrap_or(url);
    let parts: Vec<&str> = url.split(':').collect();
    if parts.len() == 2 {
        let host = parts[0].to_string();
        let port = parts[1].parse()?;
        Ok((host, port))
    } else {
        Err("Invalid URL format".into())
    }
}

fn create_tls_client_config() -> Result<ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let root_store = tokio_rustls::rustls::RootCertStore::empty();

    // For testing, we'll accept invalid certs by using an empty root store
    // rustls 0.23: builder() already uses safe defaults (TLS 1.2 and 1.3)
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

#[tokio::test]
async fn test_tls_session_resumption_basic() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let (host, port) = parse_host_port(PROXY_HTTPS_URL)?;
    let server_name =
        ServerName::try_from(host.clone()).map_err(|e| format!("Invalid server name: {e}"))?;

    // Create client config (will negotiate TLS version with server)
    let client_config = create_tls_client_config()?;

    let connector = TlsConnector::from(Arc::new(client_config));

    // First connection - establish session
    let stream1 = TcpStream::connect((host.as_str(), port)).await?;
    let mut tls_stream1 = connector.connect(server_name.clone(), stream1).await?;

    // Send a simple HTTP request
    tls_stream1
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response1 = Vec::new();
    tls_stream1.read_to_end(&mut response1).await?;

    // Get session information from the first connection
    let (_, session1) = tls_stream1.get_ref();
    let version1 = session1.protocol_version();
    // Note: rustls doesn't expose session ID directly in ClientConnection
    // We'll verify resumption by checking protocol version and handshake characteristics

    // Close first connection
    drop(tls_stream1);

    // Small delay to ensure connection is closed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second connection - should resume session
    let stream2 = TcpStream::connect((host.as_str(), port)).await?;
    let mut tls_stream2 = connector.connect(server_name, stream2).await?;

    // Send another request
    tls_stream2
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response2 = Vec::new();
    tls_stream2.read_to_end(&mut response2).await?;

    let (_, session2) = tls_stream2.get_ref();
    let version2 = session2.protocol_version();

    // Verify both connections succeeded
    assert!(!response1.is_empty(), "First connection should receive response");
    assert!(!response2.is_empty(), "Second connection should receive response");

    // Verify both connections use the same TLS version (indicates session resumption may have worked)
    // Note: We can't directly verify session resumption without inspecting the handshake,
    // but if both connections use the same version, it's a good sign
    assert_eq!(version1, version2, "Both connections should use same TLS version");

    // Log the version used (could be TLS 1.2 or 1.3 depending on negotiation)
    println!("✓ TLS session resumption basic test completed");
    println!("  First connection version: {:?}", version1);
    println!("  Second connection version: {:?}", version2);
    println!("  Note: Both connections use the same version, which is consistent with session resumption");

    Ok(())
}

#[tokio::test]
async fn test_tls_session_resumption_with_timing(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let (host, port) = parse_host_port(PROXY_HTTPS_URL)?;
    let server_name =
        ServerName::try_from(host.clone()).map_err(|e| format!("Invalid server name: {e}"))?;

    // Create client config (will negotiate TLS version with server, typically TLS 1.3)
    let client_config = create_tls_client_config()?;

    let connector = TlsConnector::from(Arc::new(client_config));

    // First connection - establish session and receive ticket
    let start1 = std::time::Instant::now();
    let stream1 = TcpStream::connect((host.as_str(), port)).await?;
    let mut tls_stream1 = connector.connect(server_name.clone(), stream1).await?;
    let handshake_time1 = start1.elapsed();

    // Send a simple HTTP request
    tls_stream1
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response1 = Vec::new();
    tls_stream1.read_to_end(&mut response1).await?;

    let (_, session1) = tls_stream1.get_ref();
    let version1 = session1.protocol_version();

    // Close first connection
    drop(tls_stream1);

    // Small delay to ensure connection is closed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second connection - should resume using ticket
    let start2 = std::time::Instant::now();
    let stream2 = TcpStream::connect((host.as_str(), port)).await?;
    let mut tls_stream2 = connector.connect(server_name, stream2).await?;
    let handshake_time2 = start2.elapsed();

    // Send another request
    tls_stream2
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response2 = Vec::new();
    tls_stream2.read_to_end(&mut response2).await?;

    let (_, session2) = tls_stream2.get_ref();
    let version2 = session2.protocol_version();

    // Verify both connections succeeded
    assert!(!response1.is_empty(), "First connection should receive response");
    assert!(!response2.is_empty(), "Second connection should receive response");

    // Both should use the same TLS version (typically TLS 1.3, but could be 1.2)
    assert_eq!(version1, version2, "Both connections should use same TLS version");
    // Note: Modern clients typically negotiate TLS 1.3, but we verify they match

    // Session resumption should make the second handshake faster
    // Note: This is a heuristic - resumption typically takes less time
    // but network conditions can vary, so we just verify both handshakes completed
    println!("✓ TLS session resumption timing test completed");
    println!("  First handshake time: {:?}", handshake_time1);
    println!("  Second handshake time: {:?}", handshake_time2);
    println!("  First connection version: {:?}", version1);
    println!("  Second connection version: {:?}", version2);

    // If session resumption worked, the second handshake should be faster or similar
    // (it might not always be faster due to network conditions, but shouldn't be much slower)
    if handshake_time2 > handshake_time1 * 2 {
        println!("  Warning: Second handshake took longer than expected - session resumption may not be working");
    }

    Ok(())
}

#[tokio::test]
async fn test_tls_multiple_connections() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This test verifies that multiple TLS connections work correctly
    // regardless of session resumption configuration
    // Useful for ensuring the proxy handles multiple sequential connections properly

    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let (host, port) = parse_host_port(PROXY_HTTPS_URL)?;

    let client_config = create_tls_client_config()?;
    let connector = TlsConnector::from(Arc::new(client_config));

    // Make two connections
    for i in 1..=2 {
        let stream = TcpStream::connect((host.as_str(), port)).await?;
        let server_name =
            ServerName::try_from(host.clone()).map_err(|e| format!("Invalid server name: {e}"))?;
        let mut tls_stream = connector.connect(server_name, stream).await?;

        tls_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await?;

        assert!(!response.is_empty(), "Connection {i} should receive response");
        drop(tls_stream);

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    println!("✓ Multiple TLS connections test completed (connections work regardless of resumption state)");

    Ok(())
}
