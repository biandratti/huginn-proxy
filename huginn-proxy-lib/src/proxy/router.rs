use crate::config::Route;

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub backend: &'a str,
    pub backend_candidates: Vec<&'a str>,
    pub fingerprinting: bool,
    pub matched_prefix: &'a str,
    pub replace_path: Option<&'a str>,
    pub rate_limit: Option<&'a crate::config::RouteRateLimitConfig>,
    pub headers: Option<&'a crate::config::HeaderManipulation>,
    pub force_new_connection: bool,
}

/// Returns true when `prefix` is a valid match for `path`.
///
/// A prefix matches if `path` starts with it AND the character immediately after is `/`
/// (sub-path) or the strings are equal (exact match). The root prefix `/` always matches.
/// This prevents `/api` from inadvertently matching `/api2`.
pub fn prefix_matches(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    prefix == "/" || path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/'
}

/// Returns the first route with the longest matching prefix.
///
/// Relies on routes being pre-sorted by prefix length descending (done in `Config::into_parts`),
/// so the first match is by definition the most specific one.
fn longest_match<'a>(path: &str, routes: &'a [Route]) -> Option<&'a Route> {
    routes.iter().find(|r| prefix_matches(path, &r.prefix))
}

pub fn pick_route<'a>(path: &str, routes: &'a [Route]) -> Option<&'a str> {
    longest_match(path, routes).map(|r| r.backend.as_str())
}

pub fn pick_route_with_fingerprinting<'a>(
    path: &str,
    routes: &'a [Route],
) -> Option<RouteMatch<'a>> {
    longest_match(path, routes).map(|first| {
        // All routes sharing the matched prefix are candidates for round-robin selection;
        // behavior flags come from the first matching route.
        let backend_candidates = routes
            .iter()
            .filter(|r| r.prefix == first.prefix)
            .map(|r| r.backend.as_str())
            .collect::<Vec<_>>();

        RouteMatch {
            backend: first.backend.as_str(),
            backend_candidates,
            fingerprinting: first.fingerprinting,
            matched_prefix: first.prefix.as_str(),
            replace_path: first.replace_path.as_deref(),
            rate_limit: first.rate_limit.as_ref(),
            headers: first.headers.as_ref(),
            force_new_connection: first.force_new_connection,
        }
    })
}
