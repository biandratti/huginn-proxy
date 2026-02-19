use crate::config::{HeaderManipulation, HeaderManipulationGroup};
use crate::telemetry::Metrics;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;

/// Apply header manipulation group (add and remove headers)
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `manipulation` - The header manipulation configuration
/// * `context` - Context string ("request" or "response") for metrics
/// * `metrics` - Optional metrics for tracking header operations
///
/// # Example
/// ```
/// use http::HeaderMap;
/// use huginn_proxy_lib::config::HeaderManipulationGroup;
/// use huginn_proxy_lib::proxy::handler::header_manipulation::apply_header_manipulation_group;
///
/// let mut headers = HeaderMap::new();
/// let manipulation = HeaderManipulationGroup::default();
///
/// apply_header_manipulation_group(&mut headers, &manipulation, "request", None);
/// ```
pub fn apply_header_manipulation_group(
    headers: &mut HeaderMap,
    manipulation: &HeaderManipulationGroup,
    context: &str,
    metrics: Option<&Arc<Metrics>>,
) {
    // Remove headers first
    if !manipulation.remove.is_empty() {
        let removed_count = remove_headers(headers, &manipulation.remove);
        if let Some(m) = metrics {
            m.record_headers_removed(removed_count, context);
        }
    }

    // Then add headers
    if !manipulation.add.is_empty() {
        let to_add: Vec<(String, String)> = manipulation
            .add
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        let added_count = add_headers(headers, &to_add);
        if let Some(m) = metrics {
            m.record_headers_added(added_count, context);
        }
    }
}

/// Apply header manipulation configuration to request headers
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `global_manipulation` - Global header manipulation configuration (optional)
/// * `route_manipulation` - Per-route header manipulation configuration (optional)
///
/// Applies global manipulation first, then route-specific manipulation.
/// This allows route-specific configuration to override global settings.
pub fn apply_request_header_manipulation(
    headers: &mut HeaderMap,
    global_manipulation: Option<&HeaderManipulation>,
    route_manipulation: Option<&HeaderManipulation>,
    metrics: Option<&Arc<Metrics>>,
) {
    // Apply global request header manipulation
    if let Some(global) = global_manipulation {
        apply_header_manipulation_group(headers, &global.request, "request", metrics);
    }

    // Apply per-route request header manipulation (overrides global)
    if let Some(route) = route_manipulation {
        apply_header_manipulation_group(headers, &route.request, "request", metrics);
    }
}

/// Apply header manipulation configuration to response headers
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `global_manipulation` - Global header manipulation configuration (optional)
/// * `route_manipulation` - Per-route header manipulation configuration (optional)
///
/// Applies global manipulation first, then route-specific manipulation.
/// This allows route-specific configuration to override global settings.
pub fn apply_response_header_manipulation(
    headers: &mut HeaderMap,
    global_manipulation: Option<&HeaderManipulation>,
    route_manipulation: Option<&HeaderManipulation>,
    metrics: Option<&Arc<Metrics>>,
) {
    // Apply global response header manipulation
    if let Some(global) = global_manipulation {
        apply_header_manipulation_group(headers, &global.response, "response", metrics);
    }

    // Apply per-route response header manipulation (overrides global)
    if let Some(route) = route_manipulation {
        apply_header_manipulation_group(headers, &route.response, "response", metrics);
    }
}

/// Remove specific headers from a header map
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `headers_to_remove` - List of header names to remove (case-insensitive)
///
/// # Example
/// ```
/// use http::HeaderMap;
/// use huginn_proxy_lib::proxy::handler::header_manipulation::remove_headers;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("server", "nginx".parse().unwrap());
///
/// remove_headers(&mut headers, &["server".to_string()]);
/// assert!(headers.get("server").is_none());
/// ```
pub fn remove_headers(headers: &mut HeaderMap, headers_to_remove: &[String]) -> u64 {
    let mut removed_count = 0u64;
    for header_name in headers_to_remove {
        if let Ok(name) = HeaderName::from_bytes(header_name.to_lowercase().as_bytes()) {
            if headers.remove(&name).is_some() {
                removed_count = removed_count.saturating_add(1);
                tracing::trace!(
                    header = %header_name,
                    "Removed header"
                );
            }
        } else {
            tracing::warn!(
                header = %header_name,
                "Failed to parse header name for removal"
            );
        }
    }
    removed_count
}

/// Add headers to a header map (overwrite if exists)
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `headers_to_add` - List of (name, value) tuples to add
///
/// # Example
/// ```
/// use http::HeaderMap;
/// use huginn_proxy_lib::proxy::handler::header_manipulation::add_headers;
///
/// let mut headers = HeaderMap::new();
/// let to_add = vec![("x-custom".to_string(), "value".to_string())];
///
/// add_headers(&mut headers, &to_add);
/// assert_eq!(headers.get("x-custom").unwrap(), "value");
/// ```
pub fn add_headers(headers: &mut HeaderMap, headers_to_add: &[(String, String)]) -> u64 {
    let mut added_count = 0u64;
    for (name, value) in headers_to_add {
        match (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            (Ok(header_name), Ok(header_value)) => {
                headers.insert(header_name, header_value);
                added_count = added_count.saturating_add(1);

                tracing::trace!(
                    header = %name,
                    value = %value,
                    "Added header"
                );
            }
            (Err(e), _) => {
                tracing::warn!(
                    header = %name,
                    error = %e,
                    "Failed to parse header name"
                );
            }
            (_, Err(e)) => {
                tracing::warn!(
                    header = %name,
                    value = %value,
                    error = %e,
                    "Failed to parse header value"
                );
            }
        }
    }
    added_count
}
