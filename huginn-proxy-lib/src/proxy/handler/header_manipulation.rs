use crate::config::{HeaderManipulation, HeaderManipulationGroup};
use http::{HeaderMap, HeaderName, HeaderValue};

/// Apply header manipulation group (add and remove headers)
///
/// # Arguments
/// * `headers` - The header map to modify
/// * `manipulation` - The header manipulation configuration
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
/// apply_header_manipulation_group(&mut headers, &manipulation);
/// ```
pub fn apply_header_manipulation_group(headers: &mut HeaderMap, manipulation: &HeaderManipulationGroup) {
    // Remove headers first
    if !manipulation.remove.is_empty() {
        remove_headers(headers, &manipulation.remove);
    }

    // Then add headers
    if !manipulation.add.is_empty() {
        let to_add: Vec<(String, String)> = manipulation
            .add
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        add_headers(headers, &to_add);
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
) {
    // Apply global request header manipulation
    if let Some(global) = global_manipulation {
        apply_header_manipulation_group(headers, &global.request);
    }

    // Apply per-route request header manipulation (overrides global)
    if let Some(route) = route_manipulation {
        apply_header_manipulation_group(headers, &route.request);
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
) {
    // Apply global response header manipulation
    if let Some(global) = global_manipulation {
        apply_header_manipulation_group(headers, &global.response);
    }

    // Apply per-route response header manipulation (overrides global)
    if let Some(route) = route_manipulation {
        apply_header_manipulation_group(headers, &route.response);
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
pub fn remove_headers(headers: &mut HeaderMap, headers_to_remove: &[String]) {
    for header_name in headers_to_remove {
        if let Ok(name) = HeaderName::from_bytes(header_name.to_lowercase().as_bytes()) {
            headers.remove(&name);

            tracing::trace!(
                header = %header_name,
                "Removed header"
            );
        } else {
            tracing::warn!(
                header = %header_name,
                "Failed to parse header name for removal"
            );
        }
    }
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
pub fn add_headers(headers: &mut HeaderMap, headers_to_add: &[(String, String)]) {
    for (name, value) in headers_to_add {
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(header_name), Ok(header_value)) => {
                headers.insert(header_name, header_value);

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
}
