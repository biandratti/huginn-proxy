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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CspConfig, CustomHeader, HstsConfig, SecurityHeaders};
    use http::Response;

    #[test]
    fn test_apply_custom_headers() {
        let config = SecurityHeaders {
            custom: vec![
                CustomHeader { name: "X-Frame-Options".to_string(), value: "DENY".to_string() },
                CustomHeader {
                    name: "X-Content-Type-Options".to_string(),
                    value: "nosniff".to_string(),
                },
            ],
            hsts: HstsConfig::default(),
            csp: CspConfig::default(),
        };

        let mut response = Response::new("body");
        apply_security_headers(&mut response, Some(&config), false);

        if let Some(header) = response.headers().get("x-frame-options") {
            if let Ok(value) = header.to_str() {
                assert_eq!(value, "DENY");
            } else {
                panic!("Failed to convert header to string");
            }
        } else {
            panic!("Header x-frame-options not found");
        }

        if let Some(header) = response.headers().get("x-content-type-options") {
            if let Ok(value) = header.to_str() {
                assert_eq!(value, "nosniff");
            } else {
                panic!("Failed to convert header to string");
            }
        } else {
            panic!("Header x-content-type-options not found");
        }
    }

    #[test]
    fn test_hsts_header_https_only() {
        let config = SecurityHeaders {
            custom: vec![],
            hsts: HstsConfig {
                enabled: true,
                max_age: 31536000,
                include_subdomains: true,
                preload: false,
            },
            csp: CspConfig::default(),
        };

        // HSTS should be added for HTTPS
        let mut response_https = Response::new("body");
        apply_security_headers(&mut response_https, Some(&config), true);
        assert!(response_https
            .headers()
            .get("strict-transport-security")
            .is_some());

        // HSTS should NOT be added for HTTP
        let mut response_http = Response::new("body");
        apply_security_headers(&mut response_http, Some(&config), false);
        assert!(response_http
            .headers()
            .get("strict-transport-security")
            .is_none());
    }

    #[test]
    fn test_hsts_header_format() {
        let hsts = HstsConfig {
            enabled: true,
            max_age: 63072000,
            include_subdomains: true,
            preload: true,
        };

        let header = build_hsts_header(&hsts);
        if let Ok(header) = header {
            let header_str = header.to_str();
            if let Ok(header_str) = header_str {
                assert!(header_str.contains("max-age=63072000"));
                assert!(header_str.contains("includeSubDomains"));
                assert!(header_str.contains("preload"));
            } else {
                panic!("Header should be valid UTF-8");
            }
        } else {
            panic!("Header should be valid");
        }
    }

    #[test]
    fn test_csp_header() {
        let config = SecurityHeaders {
            custom: vec![],
            hsts: HstsConfig::default(),
            csp: CspConfig {
                enabled: true,
                policy: "default-src 'self'; script-src 'self' 'unsafe-inline'".to_string(),
            },
        };

        let mut response = Response::new("body");
        apply_security_headers(&mut response, Some(&config), false);

        if let Some(header) = response.headers().get("content-security-policy") {
            if let Ok(value) = header.to_str() {
                assert_eq!(value, "default-src 'self'; script-src 'self' 'unsafe-inline'");
            } else {
                panic!("Failed to convert CSP header to string");
            }
        } else {
            panic!("CSP header not found");
        }
    }

    #[test]
    fn test_no_config() {
        let mut response = Response::new("body");
        apply_security_headers(&mut response, None, false);

        // No headers should be added
        assert!(response.headers().is_empty());
    }

    #[test]
    fn test_disabled_features() {
        let config = SecurityHeaders {
            custom: vec![],
            hsts: HstsConfig {
                enabled: false,
                max_age: 31536000,
                include_subdomains: true,
                preload: false,
            },
            csp: CspConfig { enabled: false, policy: "default-src 'self'".to_string() },
        };

        let mut response = Response::new("body");
        apply_security_headers(&mut response, Some(&config), true);

        // No headers should be added when features are disabled
        assert!(response.headers().is_empty());
    }
}
