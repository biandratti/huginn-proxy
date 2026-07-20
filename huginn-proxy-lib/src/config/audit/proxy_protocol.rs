//! Audit for a `proxy_protocol` mode that can never trust a peer (empty `trusted_proxies`).
//!
//! The PROXY header is only honored from an IP in `security.trusted_proxies`. When that list is
//! empty there is no peer to trust. This module owns the single source of truth for classifying that
//! gap: the runtime logger (`proxy::protocol::warn_proxy_protocol_trust_gap`) consumes [`trust_gap`]
//! to pick its log level at boot/reload, while [`proxy_protocol_trust_warnings`] surfaces the same
//! finding in `--validate` (where the runtime never runs).

use super::ConfigWarning;
use crate::config::{Config, ProxyProtocolMode};

/// A `proxy_protocol` trust gap, carrying the severity so the runtime logger can pick `error!` vs
/// `warn!` while `--validate` reports it uniformly as a warning.
pub(crate) enum TrustGap {
    /// `require` + empty `trusted_proxies`: every connection is dropped (fail-closed).
    RequireDropsAll,
    /// `optional` + empty `trusted_proxies`: the PROXY header is never parsed (degrades to `off`).
    OptionalDegradesToOff,
}

impl TrustGap {
    /// Human-readable description, shared by the runtime logger and the `--validate` audit.
    pub(crate) fn message(&self) -> &'static str {
        match self {
            TrustGap::RequireDropsAll => {
                "proxy_protocol=require but security.trusted_proxies is empty: every connection \
                 will be dropped (no peer can be trusted to send a PROXY header)"
            }
            TrustGap::OptionalDegradesToOff => {
                "proxy_protocol=optional but security.trusted_proxies is empty: no peer is trusted, \
                 the PROXY header is never parsed (effectively behaves as off)"
            }
        }
    }
}

/// Classify the trust gap for a `proxy_protocol` mode. `off`, or a `trusted_proxies` that can trust
/// at least one peer (non-empty `cidrs` or `insecure`), yields `None`.
pub(crate) fn trust_gap(mode: ProxyProtocolMode, has_trust: bool) -> Option<TrustGap> {
    if has_trust {
        return None;
    }
    match mode {
        ProxyProtocolMode::Require => Some(TrustGap::RequireDropsAll),
        ProxyProtocolMode::Optional => Some(TrustGap::OptionalDegradesToOff),
        ProxyProtocolMode::Off => None,
    }
}

/// Non-fatal audit for the `proxy_protocol` trust gap, for `--validate`.
///
/// Deliberately **not** part of `run`/[`super::all_warnings`]: at boot and on hot reload the runtime
/// already logs this via `warn_proxy_protocol_trust_gap` (at `error!`/`warn!` level), so adding it
/// there would double-log. `--validate` calls this explicitly since the runtime never runs.
pub fn proxy_protocol_trust_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    trust_gap(cfg.listen.proxy_protocol.mode, cfg.security.trusted_proxies.has_trust())
        .map(|gap| ConfigWarning {
            scope: "proxy_protocol".to_string(),
            message: gap.message().to_string(),
        })
        .into_iter()
        .collect()
}
