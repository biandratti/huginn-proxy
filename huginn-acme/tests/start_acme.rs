use huginn_acme::{start_acme, AcmeError};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const BOGUS_DIRECTORY: &str = "https://127.0.0.1:1/directory";

#[tokio::test]
async fn rejects_empty_domains() {
    let result = start_acme(
        &["ops@example.com".to_string()],
        "/tmp/huginn-acme-test",
        true,
        None,
        None,
        &[],
        CancellationToken::new(),
        None,
    )
    .await;
    assert!(matches!(result, Err(AcmeError::NoDomains)));
}

#[tokio::test]
async fn rejects_missing_directory_ca() {
    let result = start_acme(
        &["ops@example.com".to_string()],
        "/tmp/huginn-acme-test",
        false,
        None,
        Some("/nonexistent/huginn-acme/pebble-ca.pem"),
        &["api.example.com".to_string()],
        CancellationToken::new(),
        None,
    )
    .await;
    assert!(
        matches!(result, Err(AcmeError::DirectoryCaRead { .. })),
        "expected DirectoryCaRead for a missing CA path"
    );
}

#[tokio::test]
async fn rejects_empty_directory_ca() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let ca_path = std::env::temp_dir().join(format!("huginn-acme-empty-ca-{nanos}.pem"));
    std::fs::write(&ca_path, b"")?;

    let result = start_acme(
        &["ops@example.com".to_string()],
        "/tmp/huginn-acme-test",
        false,
        None,
        Some(&ca_path.to_string_lossy()),
        &["api.example.com".to_string()],
        CancellationToken::new(),
        None,
    )
    .await;
    let _ = std::fs::remove_file(&ca_path);
    assert!(
        matches!(result, Err(AcmeError::DirectoryCaEmpty { .. })),
        "expected DirectoryCaEmpty for a readable-but-empty CA bundle"
    );
    Ok(())
}

#[tokio::test]
async fn builds_one_lowercased_resolver_per_domain() -> TestResult {
    let cache_dir = std::env::temp_dir();
    let domains = vec!["API.Example.com".to_string(), "b.Test".to_string()];

    // Pre-cancel so each spawned task exits at its first poll without doing any ACME IO.
    let cancel = CancellationToken::new();
    cancel.cancel();

    let handles = start_acme(
        &["ops@example.com".to_string()],
        &cache_dir.to_string_lossy(),
        true,
        Some(BOGUS_DIRECTORY),
        None,
        &domains,
        cancel,
        None,
    )
    .await?;

    // One `(host, resolver)` pair per domain, host lowercased for case-insensitive SNI.
    assert_eq!(handles.resolvers.len(), 2);
    let hosts: Vec<&str> = handles.resolvers.iter().map(|(h, _)| h.as_str()).collect();
    assert!(hosts.contains(&"api.example.com"), "host must be lowercased: {hosts:?}");
    assert!(hosts.contains(&"b.test"), "host must be lowercased: {hosts:?}");

    // One task per domain, and every task must honor the cancellation token and exit.
    assert_eq!(handles.tasks.len(), 2);
    for task in handles.tasks {
        match timeout(Duration::from_secs(5), task).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => return Err(join_err.into()),
            Err(_elapsed) => return Err("ACME task did not exit after cancellation".into()),
        }
    }
    Ok(())
}
