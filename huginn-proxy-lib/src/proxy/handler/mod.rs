pub mod authority;
pub mod header_manipulation;
pub mod headers;
pub mod hop_by_hop;
pub mod host;
pub mod rate_limit_validation;
pub mod request;
pub mod resolve;
pub use authority::{authority_matches_sni, mutual_tls_session_matches};
pub use headers::{
    add_forwarded_headers, akamai_header_value, set_forwarded_for, tls_header_value,
};
pub use hop_by_hop::{strip_hop_by_hop, strip_request_hop_by_hop};
pub use host::{
    extract_request_host_inner, https_redirect_location, strip_host_port, strip_trailing_dot,
};
pub use rate_limit_validation::check_rate_limit;
pub use request::{handle_proxy_request, https_redirect_port};
pub use resolve::{EffectiveSecurity, resolve_security};
