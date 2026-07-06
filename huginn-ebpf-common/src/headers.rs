//! Minimal network header structs shared between the BPF kernel programs and
//! userspace tests.
//!
//! These are `#[repr(C)]` mirrors of the Linux UAPI headers that `aya-ebpf-bindings`
//! does not include. All multi-byte fields are in **network byte order** as they appear
//! on the wire (or as the BPF program reads them on a little-endian CPU without swapping).

/// Ethernet II header (14 bytes).
#[repr(C)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16, // network byte order
}

/// IEEE 802.1Q VLAN tag (4 bytes, follows EtherType 0x8100/0x88A8).
#[repr(C)]
pub struct VlanHdr {
    pub tci: u16,
    pub encapsulated_proto: u16, // network byte order
}

/// Minimal IPv4 header (no options, 20 bytes).
///
/// The first byte encodes `version` (high nibble) and `ihl` (low nibble) following
/// `__LITTLE_ENDIAN_BITFIELD` ordering on a LE CPU.
#[repr(C)]
pub struct Ip4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    /// Network byte order; contains RF/DF/MF flags and 13-bit fragment offset.
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32, // network byte order
    pub daddr: u32, // network byte order
}

impl Ip4Hdr {
    /// Extract the IP header length in 32-bit words (lower 4 bits of `version_ihl`).
    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}

/// Minimal TCP header (fixed 20 bytes).
///
/// `offset_flags` (bytes 12-13) encodes `doff` and the TCP flag bits using
/// `__LITTLE_ENDIAN_BITFIELD` ordering. As a LE `u16` (low byte first in memory):
///
/// ```text
/// bits [0-3]  = reserved (res1); bit 3 = NS/ECN Nonce Sum (RFC 3540)
/// bits [4-7]  = doff (data offset, in 32-bit words)
/// bits [8]    = FIN
/// bits [9]    = SYN
/// bits [10]   = RST
/// bits [11]   = PSH
/// bits [12]   = ACK
/// bits [13]   = URG
/// bits [14]   = ECE
/// bits [15]   = CWR
/// ```
#[repr(C)]
pub struct TcpHdr {
    pub source: u16,       // network byte order
    pub dest: u16,         // network byte order
    pub seq: u32,          // network byte order
    pub ack_seq: u32,      // network byte order
    pub offset_flags: u16, // doff + flags, LE layout described above
    pub window: u16,       // network byte order
    pub check: u16,
    pub urg_ptr: u16,
}

impl TcpHdr {
    /// TCP data offset in 32-bit words (upper 4 bits of the low byte of `offset_flags`).
    #[inline(always)]
    pub fn doff(&self) -> u8 {
        ((self.offset_flags >> 4) & 0xF) as u8
    }
    #[inline(always)]
    pub fn syn(&self) -> bool {
        (self.offset_flags >> 9) & 1 != 0
    }
    #[inline(always)]
    pub fn ack(&self) -> bool {
        (self.offset_flags >> 12) & 1 != 0
    }
    #[inline(always)]
    pub fn urg(&self) -> bool {
        (self.offset_flags >> 13) & 1 != 0
    }
    #[inline(always)]
    pub fn psh(&self) -> bool {
        (self.offset_flags >> 11) & 1 != 0
    }
    #[inline(always)]
    pub fn ece(&self) -> bool {
        (self.offset_flags >> 14) & 1 != 0
    }
    #[inline(always)]
    pub fn cwr(&self) -> bool {
        (self.offset_flags >> 15) & 1 != 0
    }
    /// ECN Nonce Sum (RFC 3540), bit 3 of the low byte.
    #[inline(always)]
    pub fn ns(&self) -> bool {
        (self.offset_flags >> 3) & 1 != 0
    }
}

/// Minimal IPv6 fixed header (40 bytes).
///
/// ```text
/// bits [31:28] = version (always 6)
/// bits [27:20] = traffic class (DSCP + ECN)
/// bits [19:0]  = flow label
/// payload_len  = length of payload + extension headers (network byte order)
/// nexthdr      = protocol of next header (e.g. 6 for TCP)
/// hop_limit    = analogous to IPv4 TTL
/// ```
#[repr(C)]
pub struct Ip6Hdr {
    /// `version` (4 bits, high) + traffic class high nibble (4 bits, low).
    pub priority_version: u8,
    /// Traffic class low nibble (4 bits, high) + flow label (20 bits, low).
    pub flow_lbl: [u8; 3],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

impl Ip6Hdr {
    /// Extract the full 8-bit traffic class (DSCP + ECN) from the packed first word.
    ///
    /// Layout: `priority_version = [ver(4) | tc_high(4)]`, `flow_lbl[0] = [tc_low(4) | fl_high(4)]`.
    #[inline(always)]
    pub fn traffic_class(&self) -> u8 {
        ((self.priority_version & 0x0F) << 4) | ((self.flow_lbl[0] & 0xF0) >> 4)
    }
}
