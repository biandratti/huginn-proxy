#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

use crate::constants::TCPOPT_MAXLEN;
use crate::headers::{IpHdr, TcpHdr};

use super::maps::{increment_syn_insert_failures, read_and_increment_syn_counter, tcp_syn_map_v4};
use super::quirk_bits;
use huginn_ebpf_common::{make_key, SynRawData};

/// Error from the TCP SYN handler.
///
/// Only one variant today: the BPF map insert failed (e.g. LRU at capacity).
/// This does **not** mean "invalid packet" or "wrong type": by the time we're called,
/// the pipeline has already validated Ethernet, IPv4, TCP, and SYN-without-ACK.
#[derive(Clone, Copy)]
pub enum TcpSynError {
    /// Could not insert (src_ip, src_port) → SynRawData into the LRU map.
    MapInsertFailed,
}

/// Handle an IPv4 TCP SYN: compute quirks, build SynRawData, insert into map.
///
/// Called from the pipeline after it has parsed Ethernet, IPv4, and TCP and
/// confirmed SYN (no ACK) and passed the destination filter.
/// `ip` and `tcp` are references to packet memory validated by the pipeline.
pub fn handle_tcp_syn_v4(
    ctx: &XdpContext,
    ip: &IpHdr,
    tcp: &TcpHdr,
    ip_hdr_len: usize,
) -> Result<(), TcpSynError> {
    let tick = read_and_increment_syn_counter();

    let quirks = quirk_bits::compute_quirks(ip, tcp);

    // ── Build map value ───────────────────────────────────────────────────────
    let tcp_hdr_len = usize::from(tcp.doff()).saturating_mul(4);
    let optlen = tcp_hdr_len
        .saturating_sub(mem::size_of::<TcpHdr>())
        .min(TCPOPT_MAXLEN);

    let mut val = SynRawData {
        src_addr: ip.saddr,
        src_port: tcp.source,
        window: tcp.window,
        optlen: optlen as u16,
        ip_ttl: ip.ttl,
        ip_olen: ip_hdr_len.saturating_sub(mem::size_of::<IpHdr>()) as u8,
        options: [0u8; 40],
        quirks,
        tick,
    };

    // Copy TCP options; must stay inline so the BPF verifier tracks packet bounds in this frame.
    // SAFETY: tcp is a valid ref to packet memory; options start immediately after the header.
    let opts_ptr = unsafe { (tcp as *const TcpHdr as *const u8).add(mem::size_of::<TcpHdr>()) };
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
        // SAFETY: we checked next_ptr <= data_end before reading.
        val.options[i] = unsafe { *byte_ptr };
    }

    let key = make_key(ip.saddr, tcp.source);
    if tcp_syn_map_v4.insert(&key, &val, 0).is_err() {
        increment_syn_insert_failures();
        return Err(TcpSynError::MapInsertFailed);
    }
    Ok(())
}
