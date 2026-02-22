/// Raw data extracted from a TCP SYN packet via the XDP eBPF program.
///
/// This is a mirror of the `tcp_syn_val` C struct in `bpf/xdp.c`.
/// The layout must match exactly — both are `#[repr(C)]` with the same field order.
///
/// Fields in network byte order: `seq`, `src_addr`, `src_port`, `window`.
/// Fields in host byte order: `tick`, `optlen`, `ip_ttl`, `options`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SynRawData {
    /// Monotonic counter at capture time (for ordering/debugging)
    pub tick: u64,
    /// TCP sequence number (network byte order)
    pub seq: u32,
    /// Source IP address (network byte order)
    pub src_addr: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// TCP window size (network byte order)
    pub window: u16,
    /// Length of captured TCP options (host byte order)
    pub optlen: u16,
    /// IP TTL
    pub ip_ttl: u8,
    /// Explicit padding to match C struct alignment (8-byte aligned → 64 bytes total)
    pub _pad: u8,
    /// Raw TCP options bytes (up to 40 bytes)
    pub options: [u8; 40],
}

impl Default for SynRawData {
    fn default() -> Self {
        Self {
            tick: 0,
            seq: 0,
            src_addr: 0,
            src_port: 0,
            window: 0,
            optlen: 0,
            ip_ttl: 0,
            _pad: 0,
            options: [0u8; 40],
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
        // 8 + 4 + 4 + 2 + 2 + 2 + 1 + 1 + 40 = 64 bytes
        assert_eq!(std::mem::size_of::<SynRawData>(), 64);
    }
}
