use huginn_acme::dir_cache::DirCache;
use rustls_acme::CertCache;
use tempfile::tempdir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_DIR_URL: &str = "https://acme.example.com/directory";

async fn store_cert(cache: &DirCache, payload: &[u8]) -> TestResult {
    let domains = vec!["example.com".to_string()];
    cache.store_cert(&domains, TEST_DIR_URL, payload).await?;
    Ok(())
}

#[tokio::test]
async fn layout_separates_accounts_from_certs() -> TestResult {
    let tmp = tempdir()?;
    let cache = DirCache::new(tmp.path(), "api.example.com");

    assert_eq!(cache.account_dir, tmp.path().join("accounts"));
    assert_eq!(cache.cert_dir, tmp.path().join("api.example.com"));
    assert_ne!(cache.account_dir, cache.cert_dir);
    Ok(())
}

#[tokio::test]
async fn verify_write_permissions_cleans_up_probe() -> TestResult {
    let tmp = tempdir()?;
    let cache = DirCache::new(tmp.path(), "example.com");

    cache.verify_write_permissions().await?;

    let entries: Vec<_> = std::fs::read_dir(&cache.cert_dir)?
        .filter_map(|e| e.ok())
        .collect();
    assert!(entries.is_empty(), "verify_write_permissions must clean up its probe file");
    Ok(())
}

#[tokio::test]
async fn verify_write_permissions_fails_on_nonexistent_uncreateable_path() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let cache = DirCache::new("/proc/huginn-acme-test", "example.com");
    assert!(
        cache.verify_write_permissions().await.is_err(),
        "expected error for unwritable path"
    );
}

#[cfg(unix)]
mod unix_permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn mode_of(path: &Path) -> Result<u32, std::io::Error> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o7777)
    }

    #[tokio::test]
    async fn new_file_is_0600_and_new_dir_is_0700() -> TestResult {
        let tmp = tempdir()?;
        let cache = DirCache::new(tmp.path(), "example.com");

        store_cert(&cache, b"cert-payload").await?;

        assert_eq!(mode_of(&cache.cert_dir)?, 0o700, "new cert dir should be 0700");

        let entries: Vec<_> = std::fs::read_dir(&cache.cert_dir)?
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "expected exactly one cert file");
        assert_eq!(mode_of(&entries[0].path())?, 0o600, "cert file should be 0600");
        Ok(())
    }

    #[tokio::test]
    async fn verify_creates_dir_with_0700() -> TestResult {
        let tmp = tempdir()?;
        let cache = DirCache::new(tmp.path(), "example.com");

        cache.verify_write_permissions().await?;

        assert_eq!(mode_of(&cache.cert_dir)?, 0o700, "cert dir created by verify should be 0700");
        Ok(())
    }

    #[tokio::test]
    async fn existing_dir_mode_is_preserved() -> TestResult {
        let tmp = tempdir()?;
        let cache = DirCache::new(tmp.path(), "example.com");

        std::fs::create_dir_all(&cache.cert_dir)?;
        std::fs::set_permissions(&cache.cert_dir, std::fs::Permissions::from_mode(0o755))?;

        store_cert(&cache, b"payload").await?;

        assert_eq!(mode_of(&cache.cert_dir)?, 0o755, "pre-existing dir mode must be preserved");
        Ok(())
    }

    #[tokio::test]
    async fn existing_file_mode_is_preserved_on_overwrite() -> TestResult {
        let tmp = tempdir()?;
        let cache = DirCache::new(tmp.path(), "example.com");

        store_cert(&cache, b"first").await?;

        let entries: Vec<_> = std::fs::read_dir(&cache.cert_dir)?
            .filter_map(|e| e.ok())
            .collect();
        let cert_path = entries[0].path();
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644))?;

        store_cert(&cache, b"second").await?;

        assert_eq!(mode_of(&cert_path)?, 0o644, "pre-existing file mode must be preserved");
        assert_eq!(std::fs::read(&cert_path)?, b"second");
        Ok(())
    }
}
