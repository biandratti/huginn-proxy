use crate::config::{IpFilterConfig, IpFilterMode};
use std::net::IpAddr;

/// Check if an IP address is allowed based on the filter configuration
///
/// Returns `true` if the IP should be allowed, `false` if it should be blocked.
///
/// # Logic:
/// - If mode is `IpFilterMode::Disabled`: always allow
/// - If mode is `IpFilterMode::Allowlist`: allow only if IP matches allowlist
/// - If mode is `IpFilterMode::Denylist`: block if IP matches denylist
pub fn is_ip_allowed(ip: IpAddr, config: &IpFilterConfig) -> bool {
    match config.mode {
        IpFilterMode::Disabled => true,
        IpFilterMode::Allowlist => {
            // Allow only if IP matches any entry in allowlist
            if config.allowlist.is_empty() {
                // Empty allowlist = deny all
                return false;
            }
            config.allowlist.iter().any(|net| net.contains(&ip))
        }
        IpFilterMode::Denylist => {
            // Block if IP matches any entry in denylist
            if config.denylist.is_empty() {
                // Empty denylist = allow all
                return true;
            }
            !config.denylist.iter().any(|net| net.contains(&ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::str::FromStr;

    fn parse_networks(addrs: &[&str]) -> Vec<IpNet> {
        addrs
            .iter()
            .filter_map(|s| IpNet::from_str(s).ok())
            .collect()
    }

    #[test]
    fn test_disabled_mode() {
        let config =
            IpFilterConfig { mode: IpFilterMode::Disabled, allowlist: vec![], denylist: vec![] };

        let ip = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(ip, &config));
    }

    #[test]
    fn test_allowlist_single_ip() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Allowlist,
            allowlist: parse_networks(&["127.0.0.1/32"]),
            denylist: vec![],
        };

        let allowed_ip = IpAddr::from_str("127.0.0.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_ip, &config));

        let blocked_ip = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_ip, &config));
    }

    #[test]
    fn test_allowlist_cidr() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Allowlist,
            allowlist: parse_networks(&["192.168.1.0/24"]),
            denylist: vec![],
        };

        let allowed_ip1 = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_ip1, &config));

        let allowed_ip2 = IpAddr::from_str("192.168.1.254").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_ip2, &config));

        let blocked_ip = IpAddr::from_str("192.168.2.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_ip, &config));
    }

    #[test]
    fn test_allowlist_multiple_networks() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Allowlist,
            allowlist: parse_networks(&["127.0.0.1/32", "192.168.1.0/24", "10.0.0.0/8"]),
            denylist: vec![],
        };

        let localhost = IpAddr::from_str("127.0.0.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(localhost, &config));

        let private1 = IpAddr::from_str("192.168.1.100").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(private1, &config));

        let private2 = IpAddr::from_str("10.5.10.20").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(private2, &config));

        let blocked = IpAddr::from_str("8.8.8.8").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked, &config));
    }

    #[test]
    fn test_denylist_single_ip() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Denylist,
            allowlist: vec![],
            denylist: parse_networks(&["192.168.1.100/32"]),
        };

        let blocked_ip = IpAddr::from_str("192.168.1.100").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_ip, &config));

        let allowed_ip = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_ip, &config));
    }

    #[test]
    fn test_denylist_cidr() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Denylist,
            allowlist: vec![],
            denylist: parse_networks(&["192.168.1.0/24"]),
        };

        let blocked_ip1 = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_ip1, &config));

        let blocked_ip2 = IpAddr::from_str("192.168.1.254").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_ip2, &config));

        let allowed_ip = IpAddr::from_str("192.168.2.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_ip, &config));
    }

    #[test]
    fn test_ipv6_allowlist() {
        let config = IpFilterConfig {
            mode: IpFilterMode::Allowlist,
            allowlist: parse_networks(&["::1/128", "2001:db8::/32"]),
            denylist: vec![],
        };

        let localhost_v6 =
            IpAddr::from_str("::1").unwrap_or(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(is_ip_allowed(localhost_v6, &config));

        let allowed_v6 =
            IpAddr::from_str("2001:db8::1").unwrap_or(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(is_ip_allowed(allowed_v6, &config));

        let blocked_v6 =
            IpAddr::from_str("2001:db9::1").unwrap_or(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_ip_allowed(blocked_v6, &config));
    }

    #[test]
    fn test_empty_allowlist_denies_all() {
        let config =
            IpFilterConfig { mode: IpFilterMode::Allowlist, allowlist: vec![], denylist: vec![] };

        let ip = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(!is_ip_allowed(ip, &config));
    }

    #[test]
    fn test_empty_denylist_allows_all() {
        let config =
            IpFilterConfig { mode: IpFilterMode::Denylist, allowlist: vec![], denylist: vec![] };

        let ip = IpAddr::from_str("192.168.1.1").unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert!(is_ip_allowed(ip, &config));
    }
}
