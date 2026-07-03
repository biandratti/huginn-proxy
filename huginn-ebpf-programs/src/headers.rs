// ── Network header definitions ────────────────────────────────────────────────
//
// aya-ebpf-bindings does not include ethernet/IP/TCP headers (those are UAPI
// network headers, not BPF-specific). We define minimal versions here.

#[repr(C)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16, // network byte order
}

#[repr(C)]
pub struct VlanHdr {
    pub tci: u16,
    pub encapsulated_proto: u16, // network byte order
}

/// Minimal IPv4 header (no options).
/// The first byte encodes `ihl` (low nibble) and `version` (high nibble)
/// following `__LITTLE_ENDIAN_BITFIELD` ordering.
#[repr(C)]
pub struct Ip4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16, // network byte order; contains DF/MF/offset flags
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32, // network byte order
    pub daddr: u32, // network byte order
}

impl Ip4Hdr {
    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        // On LE: ihl is the lower 4 bits of the first byte
        self.version_ihl & 0x0F
    }
}

/// Minimal TCP header (fixed 20 bytes).
/// Bytes 12-13 encode `doff` and the flag bits using `__LITTLE_ENDIAN_BITFIELD`.
///
/// As a LE u16 (low byte first in memory):
///   bits [0-3]  = reserved (res1); bit 3 is NS/ECN Nonce Sum per RFC 3540
///   bits [4-7]  = doff (data offset)
///   bits [8]    = FIN
///   bits [9]    = SYN
///   bits [10]   = RST
///   bits [11]   = PSH
///   bits [12]   = ACK
///   bits [13]   = URG
///   bits [14]   = ECE
///   bits [15]   = CWR
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

/// Minimal IPv6 fixed header (40 bytes).
///
/// Layout (big-endian on wire):
///   bits [31:28] = version (always 6)
///   bits [27:20] = traffic class (DSCP + ECN)
///   bits [19:0]  = flow label
///   payload_len  = length of payload + extension headers
///   nexthdr      = protocol of next header (e.g. 6 for TCP)
///   hop_limit    = analogous to IPv4 TTL
#[repr(C)]
pub struct Ip6Hdr {
    /// Version (4 bits) + traffic class high (4 bits).
    pub priority_version: u8,
    /// Traffic class low (4 bits) + flow label high (4 bits) + flow label low (16 bits).
    pub flow_lbl: [u8; 3],
    pub payload_len: u16,
    pub nexthdr: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

impl Ip6Hdr {
    /// Extract the full traffic class byte (bits 4..11 of the first 32-bit word).
    /// Layout: `priority_version` = [ver(4) | tc_high(4)], `flow_lbl[0]` = [tc_low(4) | fl_high(4)].
    #[inline(always)]
    pub fn traffic_class(&self) -> u8 {
        ((self.priority_version & 0x0F) << 4) | ((self.flow_lbl[0] & 0xF0) >> 4)
    }
}

impl TcpHdr {
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
    #[inline(always)]
    pub fn ns(&self) -> bool {
        (self.offset_flags >> 3) & 1 != 0
    }
}
