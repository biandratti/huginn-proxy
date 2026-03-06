use aya_ebpf::programs::XdpContext;
use core::mem;

use super::constants::*;
use super::headers::{EthHdr, IpHdr, TcpHdr, VlanHdr};
use super::helpers::ptr_at;
use super::maps::{dst_ip, dst_port, syn_counter, tcp_syn_map_v4};
use super::quirk_bits;
use super::syn_raw::{make_key, SynRawData};

/// Main XDP dispatch: parse ethernet/VLAN, route IPv4 TCP SYN packets.
pub fn try_xdp_syn(ctx: &XdpContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // ── Ethernet ──────────────────────────────────────────────────────────────
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

    // ── IPv4 ──────────────────────────────────────────────────────────────────
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

    // ── TCP ───────────────────────────────────────────────────────────────────
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

    // ── Quirk bitmask ─────────────────────────────────────────────────────────
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

    // ── Build map value ───────────────────────────────────────────────────────
    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    let optlen = tcp_hdr_len
        .saturating_sub(mem::size_of::<TcpHdr>())
        .min(TCPOPT_MAXLEN);

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

    // ── Copy TCP options ───────────────────────────────────────────────────────
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
    tcp_syn_map_v4.insert(&key, &val, 0).map_err(|_| ())
}
