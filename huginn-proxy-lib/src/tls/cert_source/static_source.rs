use std::path::Path;
use std::sync::Arc;

use crate::error::ProxyError;

use super::{read_certs_and_keys, ServerCertsKeys};

/// Certificates loaded once at startup. Never reloaded.
pub struct StaticCertSource {
    certs: Arc<ServerCertsKeys>,
}

impl StaticCertSource {
    pub async fn load(cert_path: &Path, key_path: &Path) -> Result<Self, ProxyError> {
        let certs = read_certs_and_keys(cert_path, key_path).await?;
        Ok(Self { certs: Arc::new(certs) })
    }

    pub(super) fn current(&self) -> Arc<ServerCertsKeys> {
        Arc::clone(&self.certs)
    }
}
