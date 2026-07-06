//! BPF map key encoding: parity between userspace (make_bpf_key_v4/v6) and the shared
//! kernel/userspace implementation in huginn_ebpf_common. A mismatch here means proxy
//! lookups would never hit kernel map entries.

use std::net::{Ipv4Addr, Ipv6Addr};

use huginn_ebpf::probe::{make_bpf_key_v4, make_bpf_key_v6};
use huginn_ebpf_common::{make_key_v4, make_key_v6};

/// make_bpf_key must produce the same u64 as common::make_key for the same (ip, port)
/// in network order. Otherwise lookups from the proxy would never match kernel map entries.
#[test]
fn test_make_bpf_key_parity_with_common() {
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let port = 443u16;

    let bpf_key = make_bpf_key_v4(ip, port);
    let ip_ne = u32::from_ne_bytes(ip.octets());
    let port_ne = u16::from_ne_bytes(port.to_be_bytes());
    let common_key = make_key_v4(ip_ne, port_ne);

    assert_eq!(
        bpf_key, common_key,
        "make_bpf_key_v4 and common::make_key_v4 must match for daemon/proxy interface"
    );
}

#[test]
fn test_make_bpf_key_parity_multiple_cases() {
    let cases = [
        (Ipv4Addr::new(0, 0, 0, 0), 0u16),
        (Ipv4Addr::new(192, 168, 1, 1), 80u16),
        (Ipv4Addr::new(255, 255, 255, 255), 65535u16),
    ];
    for (ip, port) in cases {
        let bpf_key = make_bpf_key_v4(ip, port);
        let ip_ne = u32::from_ne_bytes(ip.octets());
        let port_ne = u16::from_ne_bytes(port.to_be_bytes());
        let common_key = make_key_v4(ip_ne, port_ne);
        assert_eq!(bpf_key, common_key, "parity for {ip}:{port}");
    }
}

#[test]
fn test_make_bpf_key_deterministic() {
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let port = 12345u16;
    let k1 = make_bpf_key_v4(ip, port);
    let k2 = make_bpf_key_v4(ip, port);
    assert_eq!(k1, k2);
}

#[test]
fn test_make_bpf_key_different_ips() {
    let k1 = make_bpf_key_v4(Ipv4Addr::new(10, 0, 0, 1), 80);
    let k2 = make_bpf_key_v4(Ipv4Addr::new(10, 0, 0, 2), 80);
    assert_ne!(k1, k2);
}

#[test]
fn test_make_bpf_key_different_ports() {
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let k1 = make_bpf_key_v4(ip, 80);
    let k2 = make_bpf_key_v4(ip, 443);
    assert_ne!(k1, k2);
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

#[test]
fn test_make_bpf_key_v6_parity_with_common() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let port = 443u16;

    let bpf_key = make_bpf_key_v6(ip, port);
    let port_ne = u16::from_ne_bytes(port.to_be_bytes());
    let common_key = make_key_v6(ip.octets(), port_ne);

    assert_eq!(
        bpf_key, common_key,
        "make_bpf_key_v6 and common::make_key_v6 must match for daemon/proxy interface"
    );
}

#[test]
fn test_make_bpf_key_v6_parity_multiple_cases() {
    let cases: &[(Ipv6Addr, u16)] = &[
        (Ipv6Addr::UNSPECIFIED, 0),
        (Ipv6Addr::LOCALHOST, 80),
        (Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 1), 8080),
        (
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            65535,
        ),
    ];
    for (ip, port) in cases {
        let bpf_key = make_bpf_key_v6(*ip, *port);
        let port_ne = u16::from_ne_bytes(port.to_be_bytes());
        let common_key = make_key_v6(ip.octets(), port_ne);
        assert_eq!(bpf_key, common_key, "parity for {ip}:{port}");
    }
}

#[test]
fn test_make_bpf_key_v6_deterministic() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let k1 = make_bpf_key_v6(ip, 443);
    let k2 = make_bpf_key_v6(ip, 443);
    assert_eq!(k1, k2);
}

#[test]
fn test_make_bpf_key_v6_different_ips() {
    let k1 = make_bpf_key_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80);
    let k2 = make_bpf_key_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 80);
    assert_ne!(k1, k2);
}

#[test]
fn test_make_bpf_key_v6_different_ports() {
    let ip = Ipv6Addr::LOCALHOST;
    let k1 = make_bpf_key_v6(ip, 80);
    let k2 = make_bpf_key_v6(ip, 443);
    assert_ne!(k1, k2);
}

#[test]
fn test_make_bpf_key_v6_layout_is_18_bytes() {
    let key = make_bpf_key_v6(Ipv6Addr::LOCALHOST, 8080);
    assert_eq!(key.len(), 18);
}

#[test]
fn test_make_bpf_key_v6_port_in_network_order() {
    // Port 0x1234 should appear as [0x12, 0x34] at bytes 16-17.
    let key = make_bpf_key_v6(Ipv6Addr::UNSPECIFIED, 0x1234);
    assert_eq!(key[16], 0x12);
    assert_eq!(key[17], 0x34);
}
