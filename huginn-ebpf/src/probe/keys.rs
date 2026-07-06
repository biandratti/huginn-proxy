use std::net::{Ipv4Addr, Ipv6Addr};

/// BPF map key for IPv4 lookup. Must match kernel `make_key_v4`.
pub fn make_bpf_key_v4(src_ip: Ipv4Addr, src_port: u16) -> u64 {
    // ip->saddr: network-order bytes [a,b,c,d] read by LE CPU = u32::from_ne_bytes([a,b,c,d])
    let ip_ne = u32::from_ne_bytes(src_ip.octets());
    // tcp->source: network-order port bytes [hi,lo] read by LE CPU
    let port_ne = u16::from_ne_bytes(src_port.to_be_bytes());
    (u64::from(ip_ne) << 16) | u64::from(port_ne)
}

/// BPF map key for IPv6 lookup. Must match kernel `make_key_v6`.
pub fn make_bpf_key_v6(src_ip: Ipv6Addr, src_port: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..16].copy_from_slice(&src_ip.octets());
    let port_be = src_port.to_be_bytes();
    key[16] = port_be[0];
    key[17] = port_be[1];
    key
}
