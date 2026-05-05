use crate::config::SecurityHeaders;
use http::{HeaderName, HeaderValue, Response};

/// Apply security headers to an HTTP response
///
/// This function adds security headers to outgoing responses based on the provided configuration.
/// Headers are applied in the following order:
/// 1. Custom headers (user-defined)
/// 2. HSTS (if enabled and connection is HTTPS)
/// 3. CSP (if enabled)
///
/// # Arguments
/// * `response` - Mutable reference to the HTTP response
/// * `config` - Optional security headers configuration
/// * `is_https` - Whether the connection is HTTPS (required for HSTS)
pub fn apply_security_headers<T>(
    response: &mut Response<T>,
    config: Option<&SecurityHeaders>,
    is_https: bool,
) {
    let Some(config) = config else {
        return;
    };

    for header in &config.custom {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name.as_bytes()),
            HeaderValue::from_str(&header.value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }

    if is_https && config.hsts.enabled {
        if let Ok(hsts_value) = build_hsts_header(&config.hsts) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("strict-transport-security"), hsts_value);
        }
    }

    if config.csp.enabled {
        if let Ok(csp_value) = HeaderValue::from_str(&config.csp.policy) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("content-security-policy"), csp_value);
        }
    }
}

/// Build HSTS header value from configuration
fn build_hsts_header(
    hsts: &crate::config::HstsConfig,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    let mut parts = vec![format!("max-age={}", hsts.max_age)];

    if hsts.include_subdomains {
        parts.push("includeSubDomains".to_string());
    }

    if hsts.preload {
        parts.push("preload".to_string());
    }

    HeaderValue::from_str(&parts.join("; "))
}
