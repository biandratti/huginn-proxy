#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

use crate::constants::TCPOPT_MAXLEN;
use crate::headers::{IpHdr, TcpHdr};

use super::maps::{syn_counter, tcp_syn_map_v4};
use super::quirk_bits;
use super::syn_raw::{make_key, SynRawData};

/// Handle an IPv4 TCP SYN: compute quirks, build SynRawData, insert into map.
///
/// Called from the pipeline after it has parsed Ethernet, IPv4, and TCP and
/// confirmed SYN (no ACK) and passed the destination filter.
pub fn handle_tcp_syn_v4(
    ctx: &XdpContext,
    ip: *const IpHdr,
    tcp: *const TcpHdr,
    ip_hdr_len: usize,
) -> Result<(), ()> {
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
    let df = frag_off & crate::constants::IP_DF != 0;

    if df {
        quirks |= quirk_bits::DF;
    }
    if df && ip_id != 0 {
        quirks |= quirk_bits::NONZERO_ID;
    }
    if !df && ip_id == 0 {
        quirks |= quirk_bits::ZERO_ID;
    }
    if frag_off & crate::constants::IP_RF != 0 {
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
    let opts_ptr = unsafe { (tcp as *const u8).add(mem::size_of::<TcpHdr>()) };
    let data_end = ctx.data_end();
    for i in 0..TCPOPT_MAXLEN {
        if i >= optlen {
            break;
        }
        let byte_ptr = unsafe { opts_ptr.add(i) };
        let next_ptr = unsafe { byte_ptr.add(1) };
        if next_ptr as usize > data_end {
            break;
        }
        val.options[i] = unsafe { *byte_ptr };
    }

    let key = make_key(unsafe { (*ip).saddr }, unsafe { (*tcp).source });
    tcp_syn_map_v4.insert(&key, &val, 0).map_err(|_| ())
}
