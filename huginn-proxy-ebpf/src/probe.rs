use std::net::Ipv4Addr;

use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, EbpfLoader};
use tracing::{info, warn};

use crate::types::SynRawData;
use crate::EbpfError;

/// Raw bytes of the compiled XDP BPF object, embedded at compile time.
/// `include_bytes_aligned!` ensures 8-byte alignment required by aya's ELF parser.
static XDP_BPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp.bpf.o"));

/// Manages the eBPF XDP program lifecycle and provides SYN data lookups.
///
/// The probe attaches an XDP program to a network interface that captures
/// TCP SYN packets and stores them in a BPF LRU hash map. When an HTTP
/// connection arrives, call `lookup()` with the client's IP+port to retrieve
/// the SYN data captured moments earlier.
pub struct EbpfProbe {
    /// Loaded eBPF object — keeps maps alive while probe exists
    _ebpf: Ebpf,
    /// Name of the interface this probe is attached to (for logging)
    interface: String,
}

impl EbpfProbe {
    /// Load the XDP BPF program and attach it to the given network interface.
    ///
    /// # Parameters
    /// - `interface`: network interface name (e.g., `"eth0"`)
    /// - `dst_ip`: proxy listen IP. `0.0.0.0` disables the IP filter (listen on all interfaces).
    /// - `dst_port`: proxy listen port. Always active as a filter.
    ///
    /// Both values are patched into the XDP program's `.rodata` via `EbpfLoader::set_global`
    /// before the kernel loads the program, matching `cilium/ebpf`'s `spec.Variables` pattern.
    pub fn new(interface: &str, dst_ip: Ipv4Addr, dst_port: u16) -> Result<Self, EbpfError> {
        // XDP compares ip->daddr and tcp->dest (both network-byte-order fields) against these
        // globals. On a little-endian CPU, network-order bytes [a,b,c,d] in the packet are read
        // as u32::from_ne_bytes([a,b,c,d]). We replicate the same encoding here so the
        // comparison in xdp.c works correctly.
        //
        // 0.0.0.0 → bpf_dst_ip = 0 → XDP skips the IP check (captures all destinations).
        let bpf_dst_ip: u32 = if dst_ip.is_unspecified() {
            0
        } else {
            u32::from_ne_bytes(dst_ip.octets())
        };

        // tcp->dest in network byte order as read by LE CPU = port.to_be()
        let bpf_dst_port: u16 = dst_port.to_be();

        let mut ebpf = EbpfLoader::new()
            .set_global("dst_ip", &bpf_dst_ip, false)
            .set_global("dst_port", &bpf_dst_port, false)
            .load(XDP_BPF_BYTES)
            .map_err(EbpfError::Load)?;

        let program: &mut Xdp = ebpf
            .program_mut("huginn_xdp_syn")
            .ok_or(EbpfError::ProgramNotFound)?
            .try_into()
            .map_err(EbpfError::ProgramType)?;

        program.load().map_err(EbpfError::ProgramLoad)?;
        program
            .attach(interface, XdpFlags::default())
            .map_err(EbpfError::Attach)?;

        let filter_ip = if dst_ip.is_unspecified() {
            "any".to_string()
        } else {
            dst_ip.to_string()
        };
        info!(interface, filter_ip, dst_port, "eBPF XDP TCP SYN fingerprinting attached");

        Ok(Self { _ebpf: ebpf, interface: interface.to_string() })
    }

    /// Look up the TCP SYN data for a client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if the SYN was not captured
    /// (e.g., program just started, IPv6 client, or map entry evicted).
    pub fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<SynRawData> {
        let map_data = self._ebpf.map("tcp_syn_map")?;
        let map = HashMap::<_, u64, SynRawData>::try_from(map_data).ok()?;

        let key = make_bpf_key(src_ip, src_port);
        match map.get(&key, 0) {
            Ok(val) => {
                // Sanity check: verify src_port matches to detect hash collisions
                let stored_port = u16::from_be(val.src_port);
                if stored_port != src_port {
                    warn!(
                        ?src_ip,
                        src_port,
                        stored_port,
                        "BPF map port mismatch — possible hash collision, ignoring"
                    );
                    return None;
                }
                Some(val)
            }
            Err(_) => None,
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Build the BPF map lookup key matching the XDP program's `make_key()`.
///
/// The XDP program: `((__u64)ip->saddr << 16) | tcp->source`
/// Both `ip->saddr` and `tcp->source` are in network byte order as seen by
/// the LE CPU (i.e., the raw BE bytes interpreted as a LE integer value).
///
/// From Rust's `Ipv4Addr` and host-byte-order port, we reconstruct the same key.
fn make_bpf_key(src_ip: Ipv4Addr, src_port: u16) -> u64 {
    // ip->saddr: network-order bytes [a,b,c,d] read by LE CPU = u32::from_ne_bytes([a,b,c,d])
    let ip_ne = u32::from_ne_bytes(src_ip.octets());
    // tcp->source: network-order port bytes [hi,lo] read by LE CPU
    let port_ne = u16::from_ne_bytes(src_port.to_be_bytes());
    (u64::from(ip_ne) << 16) | u64::from(port_ne)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_bpf_key_deterministic() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let port = 12345u16;
        let k1 = make_bpf_key(ip, port);
        let k2 = make_bpf_key(ip, port);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_make_bpf_key_different_ips() {
        let k1 = make_bpf_key(Ipv4Addr::new(10, 0, 0, 1), 80);
        let k2 = make_bpf_key(Ipv4Addr::new(10, 0, 0, 2), 80);
        assert_ne!(k1, k2);
    }
}
