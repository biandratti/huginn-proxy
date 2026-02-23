use std::net::Ipv4Addr;

use huginn_proxy_ebpf::probe::make_bpf_key;

#[test]
fn test_make_bpf_key_deterministic() {
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let port = 12345u16;
    let k1 = make_bpf_key(ip, port);
    let k2 = make_bpf_key(ip, port);
    assert_eq!(k1, k2);
}

#[test]
fn test_make_bpf_key_different_ips() {
    let k1 = make_bpf_key(Ipv4Addr::new(10, 0, 0, 1), 80);
    let k2 = make_bpf_key(Ipv4Addr::new(10, 0, 0, 2), 80);
    assert_ne!(k1, k2);
}

#[test]
fn test_make_bpf_key_different_ports() {
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let k1 = make_bpf_key(ip, 80);
    let k2 = make_bpf_key(ip, 443);
    assert_ne!(k1, k2);
}
