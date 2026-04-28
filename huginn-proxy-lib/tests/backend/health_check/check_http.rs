use std::time::Duration;

use huginn_proxy_lib::backend::{check_http, HealthCheckHttpClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestErr = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
async fn check_http_matches_status() -> Result<(), TestErr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let addr_s = format!("{addr}");

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 1024];
        if stream.read(&mut buf).await.is_err() {
            return;
        }
        const RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(RESPONSE.as_bytes()).await;
    });

    let client = HealthCheckHttpClient::new(2);
    let ok = check_http(&client, &addr_s, "/", 200, Duration::from_secs(2)).await;
    assert!(ok);
    Ok(())
}

#[tokio::test]
async fn check_http_rejects_wrong_status() -> Result<(), TestErr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let addr_s = format!("{addr}");

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await;
        const RESPONSE: &str =
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(RESPONSE.as_bytes()).await;
    });

    let client = HealthCheckHttpClient::new(2);
    let ok = check_http(&client, &addr_s, "/probe", 200, Duration::from_secs(2)).await;
    assert!(!ok);
    Ok(())
}
