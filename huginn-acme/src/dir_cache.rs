use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use aws_lc_rs::digest::{Context, SHA256};
use base64::prelude::*;
use blocking::unblock;
use rustls_acme::{AccountCache, CertCache};

use crate::constants::ACME_ACCOUNT_SUBDIR;

/// Mode for newly-created cache directories on Unix. Directories that already
/// exist are not modified; this only takes effect when the directory is actually
/// created by `DirBuilder::create`.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Mode for newly-created cache files (including private keys) on Unix.
/// Existing files retain their current mode; `OpenOptions::mode` only applies
/// when `O_CREAT` actually allocates a new inode.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Create `dir` (and any missing parent components) with mode `DIR_MODE` on Unix.
/// Existing components are not touched.
fn create_dir_secure(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIR_MODE);
    }
    builder.create(dir)
}

/// Write `contents` to `path`, creating it with mode `FILE_MODE` on Unix if it
/// does not already exist. If the file existed, its mode is preserved (the
/// content is truncated and overwritten in place).
fn write_file_secure(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(FILE_MODE);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)
}

enum FileKind {
    Account,
    Cert,
}

/// Async-safe, permission-hardened directory cache for ACME account keys and certificates.
///
/// ## Layout
///
/// ```text
/// base_dir/
///   accounts/               <- ACME account keys (one per contact+directory combination)
///     cached_account_{hash}
///   api.example.com/        <- certificate cache for that domain
///     cached_cert_{hash}
/// ```
///
/// ## Why not the built-in `rustls_acme::caches::DirCache`?
///
/// The built-in cache writes files with `std::fs::write`, which respects the
/// process umask. On most Linux systems the default umask is `022`, producing
/// world-readable `0644` files — including ACME account private keys and the
/// certificate+key PEM bundle. This implementation uses `OpenOptions::mode(0o600)`
/// for new files and `DirBuilder::mode(0o700)` for new directories, so key
/// material is only readable by the process owner.
///
/// File I/O is offloaded to a blocking thread pool via [`blocking::unblock`] so
/// async tasks are never stalled on disk operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirCache {
    pub account_dir: PathBuf,
    pub cert_dir: PathBuf,
}

impl DirCache {
    /// Create a cache for `domain` rooted at `base_dir`.
    ///
    /// Account keys are stored in `base_dir/accounts/` (shared across domains).
    /// Certificate files are stored in `base_dir/{domain}/`.
    pub fn new(base_dir: impl AsRef<Path>, domain: &str) -> Self {
        Self {
            account_dir: base_dir.as_ref().join(ACME_ACCOUNT_SUBDIR),
            cert_dir: base_dir.as_ref().join(domain),
        }
    }

    async fn read_if_exist(
        &self,
        file: impl AsRef<Path>,
        kind: FileKind,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let path = match kind {
            FileKind::Account => self.account_dir.join(file),
            FileKind::Cert => self.cert_dir.join(file),
        };
        match unblock(move || std::fs::read(&path)).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn write(
        &self,
        file: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        kind: FileKind,
    ) -> std::io::Result<()> {
        let dir = match kind {
            FileKind::Account => self.account_dir.clone(),
            FileKind::Cert => self.cert_dir.clone(),
        };
        let dir_for_create = dir.clone();
        unblock(move || create_dir_secure(&dir_for_create)).await?;
        let path = dir.join(file);
        let data = contents.as_ref().to_owned();
        unblock(move || write_file_secure(&path, &data)).await
    }

    fn cached_account_file_name(contact: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for c in contact {
            ctx.update(c.as_bytes());
            ctx.update(&[0]);
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = BASE64_URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_account_{hash}")
    }

    fn cached_cert_file_name(domains: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for d in domains {
            ctx.update(d.as_bytes());
            ctx.update(&[0]);
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = BASE64_URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_cert_{hash}")
    }

    /// Verify that both the account and certificate directories are writable.
    ///
    /// Creates a temporary probe file in each directory and removes it immediately.
    /// Call this before spawning ACME tasks so that a missing or read-only `cache_dir`
    /// fails fast at startup with a clear error, rather than silently failing to
    /// persist a newly issued certificate and burning LE rate-limit quota on every restart.
    pub async fn verify_write_permissions(&self) -> std::io::Result<()> {
        Self::verify_dir_writable(&self.account_dir).await?;
        Self::verify_dir_writable(&self.cert_dir).await?;
        Ok(())
    }

    async fn verify_dir_writable(dir: &Path) -> std::io::Result<()> {
        let dir = dir.to_owned();
        unblock(move || {
            create_dir_secure(&dir)?;
            let probe = dir.join(format!(
                ".write_test_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            ));
            write_file_secure(&probe, b"test")?;
            std::fs::remove_file(&probe)
        })
        .await
    }
}

#[async_trait]
impl CertCache for DirCache {
    type EC = std::io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let name = Self::cached_cert_file_name(domains, directory_url);
        self.read_if_exist(name, FileKind::Cert).await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let name = Self::cached_cert_file_name(domains, directory_url);
        self.write(name, cert, FileKind::Cert).await
    }
}

#[async_trait]
impl AccountCache for DirCache {
    type EA = std::io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let name = Self::cached_account_file_name(contact, directory_url);
        self.read_if_exist(name, FileKind::Account).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let name = Self::cached_account_file_name(contact, directory_url);
        self.write(name, account, FileKind::Account).await
    }
}
