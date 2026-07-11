/// BPF map key (IPv4). Network-byte-order IP and port as read on a LE CPU.
#[inline(always)]
pub fn make_key_v4(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}

/// BPF map key (IPv6). 16-byte addr + 2-byte port in wire byte order.
#[inline(always)]
pub fn make_key_v6(src_addr: [u8; 16], src_port: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..16].copy_from_slice(&src_addr);
    // src_port is NBO-as-NE: to_ne_bytes() on a LE CPU recovers the original wire bytes.
    let port_bytes = src_port.to_ne_bytes();
    key[16] = port_bytes[0];
    key[17] = port_bytes[1];
    key
}
