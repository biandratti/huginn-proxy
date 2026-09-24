use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::config::StaticConfig;
use crate::config::audit;
use crate::config::dynamic::backend::Domain;
use crate::config::parser::ConfigFormat;
use crate::config::startup::listen::ListenConfig;
use crate::config::startup::tls::{TlsConfig, default_alpn};
use crate::error::{ProxyError, Result};

pub fn load_from_path<P: AsRef<Path>>(p: P) -> Result<Config> {
    let mut cfg = parse_config_file(p.as_ref())?;
    apply_listen_tls_defaults(&mut cfg);
    validate_config(&cfg)?;
    validate_tls_section(&cfg.listen, cfg.tls.as_ref())?;
    validate_domains_against_listen(&cfg.listen, &cfg.domains)?;
    audit::run(&cfg);
    Ok(cfg)
}

/// Parse a replacement config and validate domains against the **running** listen.
///
/// Static `listen` / `[tls]` in the file are not used for cert × port rules (those
/// settings are ignored until restart). The file must still be a valid snapshot
/// (sockets, unique hosts, cert files, cross-refs).
pub fn load_from_path_for_reload<P: AsRef<Path>>(p: P, running: &StaticConfig) -> Result<Config> {
    let cfg = parse_config_file(p.as_ref())?;
    validate_config(&cfg)?;
    validate_domains_against_listen(&running.listen, &cfg.domains)?;
    audit::run(&cfg);
    Ok(cfg)
}

fn parse_config_file(path: &Path) -> Result<Config> {
    let format = ConfigFormat::from_path(path)?;
    let content = fs::read_to_string(path)
        .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;
    let mut cfg = format.parser().parse(&content)?;
    normalize_domain_hosts(&mut cfg);
    Ok(cfg)
}

/// When `port_tls` is set, fill `[tls]` if omitted and default ALPN if `alpn` is omitted.
fn apply_listen_tls_defaults(cfg: &mut Config) {
    if cfg.listen.port_tls.is_none() {
        return;
    }
    match &mut cfg.tls {
        None => {
            cfg.tls = Some(TlsConfig { alpn: Some(default_alpn()), ..TlsConfig::default() });
        }
        Some(tls) if tls.alpn.is_none() => {
            tls.alpn = Some(default_alpn());
        }
        Some(_) => {}
    }
}

/// Lowercase every domain `host` and strip a trailing `.` (the DNS root label). DNS
/// names and the HTTP `Host` header are case-insensitive (RFC 4343 / RFC 7230), and
/// `api.example.com.` names the same domain as `api.example.com` (RFC 1034 §3.1); the
/// request side applies the same two normalizations in `extract_request_host`, so
/// config and request hosts compare consistently.
fn normalize_domain_hosts(cfg: &mut Config) {
    for domain in &mut cfg.domains {
        if let Some(host) = domain.host.as_mut() {
            host.make_ascii_lowercase();
            let stripped = crate::proxy::handler::strip_trailing_dot(host).to_owned();
            *host = stripped;
        }
    }
}

/// Reject duplicate hosts and more than one catch-all (host-less) domain, which
/// would make domain selection and cert resolution disagree (routing keeps the
/// first match; the cert resolver keeps the last).
fn validate_unique_hosts(cfg: &Config) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut has_catch_all = false;
    for domain in &cfg.domains {
        match domain.host.as_deref() {
            Some("") => {
                // A `host` of "." normalizes to "" here, which is not `None`: it
                // would never match any request (an empty host is never resolved
                // by `extract_request_host`) and would silently act as a dead
                // domain entry instead of the catch-all the user likely intended.
                return Err(ProxyError::Config(
                    "Domain host must not be empty; omit `host` entirely for a \
                     catch-all domain"
                        .to_string(),
                ));
            }
            None => {
                if has_catch_all {
                    return Err(ProxyError::Config(
                        "Multiple catch-all domains (entries with no `host`); \
                         at most one is allowed"
                            .to_string(),
                    ));
                }
                has_catch_all = true;
            }
            Some(host) => {
                if !seen.insert(host) {
                    return Err(ProxyError::Config(format!("Duplicate domain host '{host}'")));
                }
            }
        }
    }
    Ok(())
}

fn validate_tls_section(listen: &ListenConfig, tls: Option<&TlsConfig>) -> Result<()> {
    if tls.is_some() && listen.port_tls.is_none() {
        return Err(ProxyError::Config(
            "[tls] requires listen.port_tls; HTTP-only listeners have no TLS handshake".to_string(),
        ));
    }
    Ok(())
}

fn validate_domains_against_listen(listen: &ListenConfig, domains: &[Domain]) -> Result<()> {
    let https_only = listen.port_tls.is_some() && listen.port.is_none();
    for domain in domains {
        let host = domain.label();
        if domain.https_redirection.is_some()
            && (listen.port.is_none() || listen.port_tls.is_none())
        {
            return Err(ProxyError::Config(format!(
                "Domain '{host}': https_redirection requires both listen.port and \
                 listen.port_tls"
            )));
        }
        let has_tls_material = domain.cert_path.is_some()
            || domain.key_path.is_some()
            || domain.client_ca_path.is_some();
        if has_tls_material && listen.port_tls.is_none() {
            return Err(ProxyError::Config(format!(
                "Domain '{host}': TLS material is configured but listen.port_tls is unset, \
                 so the listener would serve plaintext and ignore it; set port_tls or drop \
                 cert_path/key_path/client_ca_path"
            )));
        }
        if https_only && (domain.cert_path.is_none() || domain.key_path.is_none()) {
            return Err(ProxyError::Config(format!(
                "Domain '{host}': listen.port_tls is set without listen.port, so every \
                 domain must have cert_path and key_path"
            )));
        }
    }
    Ok(())
}

fn validate_config(cfg: &Config) -> Result<()> {
    cfg.listen.sockets()?;
    validate_unique_hosts(cfg)?;

    for domain in &cfg.domains {
        let host = domain.label();

        match (&domain.cert_path, &domain.key_path) {
            (Some(cert), Some(key)) => {
                if !Path::new(cert).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': certificate file not found: {cert}"
                    )));
                }
                if !Path::new(key).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': key file not found: {key}"
                    )));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ProxyError::Config(format!(
                    "Domain '{host}': cert_path and key_path must both be set or both omitted"
                )));
            }
        }

        if domain.https_redirection.is_some()
            && (domain.cert_path.is_none() || domain.key_path.is_none())
        {
            return Err(ProxyError::Config(format!(
                "Domain '{host}': https_redirection requires cert_path and key_path"
            )));
        }

        if let Some(ca) = &domain.client_ca_path {
            if domain.cert_path.is_none() || domain.key_path.is_none() {
                return Err(ProxyError::Config(format!(
                    "Domain '{host}': client_ca_path requires cert_path and key_path \
                     (mutual TLS needs the domain's own certificate)"
                )));
            }
            if !Path::new(ca).exists() {
                return Err(ProxyError::Config(format!(
                    "Domain '{host}': client CA file not found: {ca}"
                )));
            }
        }
    }

    cfg.validate_cross_refs()?;

    Ok(())
}
