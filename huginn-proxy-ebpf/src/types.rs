/// Raw data extracted from a TCP SYN packet via the XDP eBPF program.
///
/// This is a mirror of the `tcp_syn_val` C struct in `bpf/xdp.c`.
/// The layout must match exactly — both are `#[repr(C)]` with the same field order.
///
/// Layout (64 bytes):
/// ```text
/// offset  0: src_addr  u32  (network byte order)
/// offset  4: src_port  u16  (network byte order)
/// offset  6: window    u16  (network byte order)
/// offset  8: optlen    u16
/// offset 10: ip_ttl    u8
/// offset 11: _pad      u8
/// offset 12: options   [u8; 40]
/// offset 52: _pad2     [u8; 4]  (align tick to 8 bytes)
/// offset 56: tick      u64      (global SYN counter at capture time)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SynRawData {
    /// Source IP address (network byte order)
    pub src_addr: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// TCP window size (network byte order)
    pub window: u16,
    /// Length of captured TCP options
    pub optlen: u16,
    /// IP TTL
    pub ip_ttl: u8,
    /// Explicit padding to match C struct alignment
    pub _pad: u8,
    /// Raw TCP options bytes (up to 40 bytes)
    pub options: [u8; 40],
    /// Explicit padding to align `tick` to 8-byte boundary (offset 52→56)
    pub _pad2: [u8; 4],
    /// Global SYN counter value at the moment this packet was captured.
    /// Used by userspace to detect stale map entries.
    pub tick: u64,
}

impl Default for SynRawData {
    fn default() -> Self {
        Self {
            src_addr: 0,
            src_port: 0,
            window: 0,
            optlen: 0,
            ip_ttl: 0,
            _pad: 0,
            options: [0u8; 40],
            _pad2: [0u8; 4],
            tick: 0,
        }
    }
}

/// Safety: SynRawData is #[repr(C)], Copy, and has no padding beyond the explicit _pad field.
/// It can be safely read from/written to BPF maps via aya.
unsafe impl aya::Pod for SynRawData {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syn_raw_data_size() {
        // 4 + 2 + 2 + 2 + 1 + 1 + 40 + 4 + 8 = 64 bytes
        assert_eq!(std::mem::size_of::<SynRawData>(), 64);
    }
}
