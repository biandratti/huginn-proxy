//! This encoding is the interface between the eBPF daemon (XDP writes entries with this key)
//! and the reverse proxy (lookup by this key). Both must use the same formula; otherwise
//! every lookup misses. These tests lock the contract so a change here fails CI and forces
//! deploying agent and proxy together.

use huginn_ebpf_common::make_key_v4;

#[test]
fn make_key_deterministic() {
    let k1 = make_key_v4(0x0A00_0001, 443);
    let k2 = make_key_v4(0x0A00_0001, 443);
    assert_eq!(k1, k2);
}

#[test]
fn make_key_zero_zero() {
    assert_eq!(make_key_v4(0, 0), 0);
}

#[test]
fn make_key_ip_only() {
    // src_port = 0 => low 16 bits zero
    assert_eq!(make_key_v4(1, 0), 1 << 16);
    assert_eq!(make_key_v4(0x1234_5678, 0), (0x1234_5678u64) << 16);
}

#[test]
fn make_key_port_only() {
    // src_ip = 0 => high 48 bits zero
    assert_eq!(make_key_v4(0, 1), 1);
    assert_eq!(make_key_v4(0, 443), 443);
}

#[test]
fn make_key_formula() {
    let src_ip: u32 = 0x0A00_0001; // 10.0.0.1 in network order (LE read)
    let src_port: u16 = 0xBB01; // 443 in network order (LE read)
    let expected = (src_ip as u64) << 16 | (src_port as u64);
    assert_eq!(make_key_v4(src_ip, src_port), expected);
}

#[test]
fn make_key_max_bounds() {
    let k = make_key_v4(u32::MAX, u16::MAX);
    assert_eq!(k, (u32::MAX as u64) << 16 | (u16::MAX as u64));
}

#[test]
fn make_key_different_ips_different_keys() {
    let k1 = make_key_v4(0x0A00_0001, 80);
    let k2 = make_key_v4(0x0A00_0002, 80);
    assert_ne!(k1, k2);
}

#[test]
fn make_key_different_ports_different_keys() {
    let k1 = make_key_v4(0x0A00_0001, 80);
    let k2 = make_key_v4(0x0A00_0001, 443);
    assert_ne!(k1, k2);
}
