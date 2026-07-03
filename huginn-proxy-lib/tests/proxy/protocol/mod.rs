mod v1;
mod v2;

use huginn_proxy_lib::proxy::protocol::normalize_mapped_ipv4;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn normalizes_ipv4_mapped_ipv6() {
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
    assert_eq!(normalize_mapped_ipv4(mapped), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    // A plain IPv4 and a genuine IPv6 are returned unchanged.
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(normalize_mapped_ipv4(v4), v4);
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(normalize_mapped_ipv4(v6), v6);
}
