//! XDP program for TCP SYN fingerprinting.
//!
//! Captures TCP SYN packets and stores raw handshake data in a BPF LRU hash map
//! keyed by (src_ip, src_port). Direct Rust port of the former `bpf/xdp.c`.
//!
//! The map layout and global variable names (`dst_ip`, `dst_port`) are identical
//! to the C version so `huginn-proxy-ebpf/src/probe.rs` requires no changes.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    programs::XdpContext,
};

use core::mem;

/// Quirk bitmask constants extracted from IP and TCP headers.
///
/// Must match the identical module in `huginn-proxy-ebpf/src/types.rs`.
/// The `offset_of!` block below enforces layout parity at compile time.
mod quirk_bits {
    pub const DF: u32 = 1 << 0;
    pub const NONZERO_ID: u32 = 1 << 1;
    pub const ZERO_ID: u32 = 1 << 2;
    pub const MUST_BE_ZERO: u32 = 1 << 3;
    pub const ECN: u32 = 1 << 4;
    pub const SEQ_ZERO: u32 = 1 << 5;
    pub const ACK_NONZERO: u32 = 1 << 6;
    pub const NONZERO_URG: u32 = 1 << 7;
    pub const URG: u32 = 1 << 8;
    pub const PUSH: u32 = 1 << 9;
}

/// Raw data extracted from a TCP SYN packet, stored in the BPF LRU map.
///
/// Layout must match `SynRawData` in `huginn-proxy-ebpf/src/types.rs` exactly.
/// Both sides use identical `offset_of!` compile-time assertions to enforce this.
/// The canonical layout is documented in `data/huginn-proxy-analisis/bpf.md`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SynRawData {
    src_addr: u32,
    src_port: u16,
    window: u16,
    optlen: u16,
    ip_ttl: u8,
    ip_olen: u8,
    options: [u8; 40],
    quirks: u32,
    tick: u64,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SynRawData>() == 64);
    assert!(offset_of!(SynRawData, src_addr) == 0);
    assert!(offset_of!(SynRawData, src_port) == 4);
    assert!(offset_of!(SynRawData, window) == 6);
    assert!(offset_of!(SynRawData, optlen) == 8);
    assert!(offset_of!(SynRawData, ip_ttl) == 10);
    assert!(offset_of!(SynRawData, ip_olen) == 11);
    assert!(offset_of!(SynRawData, options) == 12);
    assert!(offset_of!(SynRawData, quirks) == 52);
    assert!(offset_of!(SynRawData, tick) == 56);
};

// ── Network protocol constants (network byte order on LE host) ──────────────

const ETH_P_IP: u16 = 0x0800_u16.swap_bytes();
const ETH_P_8021Q: u16 = 0x8100_u16.swap_bytes();
const ETH_P_8021AD: u16 = 0x88A8_u16.swap_bytes();

const IP_RF: u16 = 0x8000_u16.swap_bytes(); // reserved / must-be-zero
const IP_DF: u16 = 0x4000_u16.swap_bytes(); // don't fragment
const IP_MF: u16 = 0x2000_u16.swap_bytes(); // more fragments
const IP_OFFSET: u16 = 0x1FFF_u16.swap_bytes(); // fragment offset mask

const IPPROTO_TCP: u8 = 6;
const TCPOPT_MAXLEN: usize = 40;

// ── Globals patched at load time by EbpfLoader::set_global ──────────────────

#[no_mangle]
#[allow(non_upper_case_globals)]
static dst_port: u16 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static dst_ip: u32 = 0;

// ── Network header definitions ───────────────────────────────────────────────
//
// aya-ebpf-bindings does not include ethernet/IP/TCP headers (those are UAPI
// network headers, not BPF-specific). We define minimal versions here.

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16, // network byte order
}

#[repr(C)]
struct VlanHdr {
    tci: u16,
    encapsulated_proto: u16, // network byte order
}

/// Minimal IPv4 header (no options).
/// The first byte encodes `ihl` (low nibble) and `version` (high nibble)
/// following `__LITTLE_ENDIAN_BITFIELD` ordering.
#[repr(C)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16, // network byte order; contains DF/MF/offset flags
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32, // network byte order
    daddr: u32, // network byte order
}

impl IpHdr {
    #[inline(always)]
    fn ihl(&self) -> u8 {
        // On LE: ihl is the lower 4 bits of the first byte
        self.version_ihl & 0x0F
    }
}

/// Minimal TCP header (fixed 20 bytes).
/// Bytes 12-13 encode `doff` and the flag bits using `__LITTLE_ENDIAN_BITFIELD`.
///
/// As a LE u16 (low byte first in memory):
///   bits [0-3]  = reserved (res1)
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
struct TcpHdr {
    source: u16,       // network byte order
    dest: u16,         // network byte order
    seq: u32,          // network byte order
    ack_seq: u32,      // network byte order
    offset_flags: u16, // doff + flags, LE layout described above
    window: u16,       // network byte order
    check: u16,
    urg_ptr: u16,
}

impl TcpHdr {
    #[inline(always)]
    fn doff(&self) -> u8 {
        ((self.offset_flags >> 4) & 0xF) as u8
    }
    #[inline(always)]
    fn syn(&self) -> bool {
        (self.offset_flags >> 9) & 1 != 0
    }
    #[inline(always)]
    fn ack(&self) -> bool {
        (self.offset_flags >> 12) & 1 != 0
    }
    #[inline(always)]
    fn urg(&self) -> bool {
        (self.offset_flags >> 13) & 1 != 0
    }
    #[inline(always)]
    fn psh(&self) -> bool {
        (self.offset_flags >> 11) & 1 != 0
    }
    #[inline(always)]
    fn ece(&self) -> bool {
        (self.offset_flags >> 14) & 1 != 0
    }
    #[inline(always)]
    fn cwr(&self) -> bool {
        (self.offset_flags >> 15) & 1 != 0
    }
}

// ── BPF maps ─────────────────────────────────────────────────────────────────

#[map]
#[allow(non_upper_case_globals)]
static tcp_syn_map: LruHashMap<u64, SynRawData> = LruHashMap::with_max_entries(8192, 0);

#[map]
#[allow(non_upper_case_globals)]
static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

// ── Packet access helper ─────────────────────────────────────────────────────

/// Returns a const pointer to `T` at `offset` bytes from the start of the
/// packet, or `None` if the access would exceed `data_end`.
///
/// The BPF verifier accepts this pattern (explicit bounds check before cast).
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let access_end = start.checked_add(offset)?.checked_add(mem::size_of::<T>())?;
    if access_end > end {
        return None;
    }
    Some(start.checked_add(offset)? as *const T)
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[xdp]
pub fn huginn_xdp_syn(ctx: XdpContext) -> u32 {
    match try_xdp_syn(&ctx) {
        Ok(()) => aya_ebpf::bindings::xdp_action::XDP_PASS,
        Err(()) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

fn try_xdp_syn(ctx: &XdpContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // ── Ethernet ─────────────────────────────────────────────────────────────
    let eth = unsafe { ptr_at::<EthHdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<EthHdr>());

    let mut eth_type = unsafe { (*eth).h_proto };

    // Up to two VLAN tags (QinQ / 802.1ad)
    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan = unsafe { ptr_at::<VlanHdr>(ctx, offset).ok_or(())? };
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = unsafe { (*vlan).encapsulated_proto };
    }
    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan = unsafe { ptr_at::<VlanHdr>(ctx, offset).ok_or(())? };
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = unsafe { (*vlan).encapsulated_proto };
    }

    if eth_type != ETH_P_IP {
        return Ok(());
    }

    // ── IPv4 ─────────────────────────────────────────────────────────────────
    let ip = unsafe { ptr_at::<IpHdr>(ctx, offset).ok_or(())? };

    let ip_hdr_len = unsafe { usize::from((*ip).ihl()).saturating_mul(4) };
    if ip_hdr_len < mem::size_of::<IpHdr>() {
        return Ok(());
    }
    offset = offset.saturating_add(mem::size_of::<IpHdr>());

    // Drop fragmented packets
    let frag_off = unsafe { (*ip).frag_off };
    if frag_off & (IP_MF | IP_OFFSET) != 0 {
        return Ok(());
    }

    if unsafe { (*ip).protocol } != IPPROTO_TCP {
        return Ok(());
    }

    // IP destination filter (0 = capture all)
    let dst_ip_val = unsafe { core::ptr::read_volatile(&dst_ip) };
    if dst_ip_val != 0 && unsafe { (*ip).daddr } != dst_ip_val {
        return Ok(());
    }

    // Skip IP options if present
    offset = offset.saturating_add(ip_hdr_len.saturating_sub(mem::size_of::<IpHdr>()));

    // ── TCP ──────────────────────────────────────────────────────────────────
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        return Ok(());
    }

    // Port destination filter (0 = capture all)
    let dst_port_val = unsafe { core::ptr::read_volatile(&dst_port) };
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    // Only SYN (not SYN+ACK)
    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    handle_tcp_syn(ctx, ip, tcp, ip_hdr_len)
}

fn handle_tcp_syn(
    ctx: &XdpContext,
    ip: *const IpHdr,
    tcp: *const TcpHdr,
    ip_hdr_len: usize,
) -> Result<(), ()> {
    // Increment the global SYN counter and capture the tick.
    // We use a read-modify-write on the map value pointer.
    // This is non-atomic but acceptable for the fingerprinting use case
    // (tick values are used only for stale-entry detection, not strict ordering).
    let tick = if let Some(counter_ptr) = syn_counter.get_ptr_mut(0) {
        let current = unsafe { *counter_ptr };
        unsafe { *counter_ptr = current.wrapping_add(1) };
        current
    } else {
        0u64
    };

    // ── Quirk bitmask ────────────────────────────────────────────────────────
    let mut quirks: u32 = 0;
    let frag_off = unsafe { (*ip).frag_off };
    let ip_id = unsafe { (*ip).id };
    let df = frag_off & IP_DF != 0;

    if df {
        quirks |= quirk_bits::DF;
    }
    if df && ip_id != 0 {
        quirks |= quirk_bits::NONZERO_ID;
    }
    if !df && ip_id == 0 {
        quirks |= quirk_bits::ZERO_ID;
    }
    if frag_off & IP_RF != 0 {
        quirks |= quirk_bits::MUST_BE_ZERO;
    }
    if unsafe { (*tcp).ece() || (*tcp).cwr() } {
        quirks |= quirk_bits::ECN;
    }
    if unsafe { (*tcp).seq } == 0 {
        quirks |= quirk_bits::SEQ_ZERO;
    }
    if unsafe { (*tcp).ack_seq } != 0 {
        quirks |= quirk_bits::ACK_NONZERO;
    }
    if unsafe { (*tcp).urg_ptr } != 0 {
        quirks |= quirk_bits::NONZERO_URG;
    }
    if unsafe { (*tcp).urg() } {
        quirks |= quirk_bits::URG;
    }
    if unsafe { (*tcp).psh() } {
        quirks |= quirk_bits::PUSH;
    }

    // ── Build map value ──────────────────────────────────────────────────────
    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    let optlen = tcp_hdr_len.saturating_sub(mem::size_of::<TcpHdr>()).min(TCPOPT_MAXLEN);

    let mut val = SynRawData {
        src_addr: unsafe { (*ip).saddr },
        src_port: unsafe { (*tcp).source },
        window: unsafe { (*tcp).window },
        optlen: optlen as u16,
        ip_ttl: unsafe { (*ip).ttl },
        ip_olen: ip_hdr_len.saturating_sub(mem::size_of::<IpHdr>()) as u8,
        options: [0u8; 40],
        quirks,
        tick,
    };

    // ── Copy TCP options ──────────────────────────────────────────────────────
    //
    // Derive the options pointer directly from `tcp` (PTR_TO_PACKET), mirroring
    // the C pattern:  __u8 *options = (__u8 *)(tcp + 1);
    //
    // Calling ptr_at() in a loop re-loads ctx.data() each iteration, which
    // causes the BPF verifier to lose PTR_TO_PACKET tracking (r=0, unverifiable).
    // Using tcp-derived pointer keeps PTR_TO_PACKET type throughout the loop,
    // so the per-byte bounds check (byte_ptr + 1 > data_end) is accepted.
    let opts_ptr = unsafe { (tcp as *const u8).add(mem::size_of::<TcpHdr>()) };
    let data_end = ctx.data_end();
    for i in 0..TCPOPT_MAXLEN {
        if i >= optlen {
            break;
        }
        let byte_ptr = unsafe { opts_ptr.add(i) };
        // Use pointer arithmetic (not integer +1) so the BPF verifier keeps
        // PTR_TO_PACKET type on the bounds-check register and extends the
        // readable range after the check. Integer saturating_add(1) demotes
        // the register to SCALAR, breaking the verifier's range tracking.
        let next_ptr = unsafe { byte_ptr.add(1) };
        if next_ptr as usize > data_end {
            break;
        }
        val.options[i] = unsafe { *byte_ptr };
    }

    let key = make_key(unsafe { (*ip).saddr }, unsafe { (*tcp).source });
    tcp_syn_map.insert(&key, &val, 0).map_err(|_| ())
}

#[inline(always)]
fn make_key(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}

// ── Required for no_std + no_main ────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
