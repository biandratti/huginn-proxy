use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::HashMap;
use tracing::{debug, warn};

use crate::types::{SynRawDataV4, SynRawDataV6};

use super::counters::is_stale;
use super::keys::{make_bpf_key_v4, make_bpf_key_v6};
use super::EbpfProbe;

impl EbpfProbe {
    /// Look up the TCP SYN data for an IPv6 client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if:
    /// - the SYN was not captured (program just started, map entry evicted), or
    /// - the entry is stale (more than 2x `syn_map_max_entries` SYNs have arrived since capture).
    pub fn lookup_v6(&self, src_ip: Ipv6Addr, src_port: u16) -> Option<SynRawDataV6> {
        let syn_map = self.syn_map_v6()?;
        let map = HashMap::<_, [u8; 18], SynRawDataV6>::try_from(syn_map).ok()?;

        let key = make_bpf_key_v6(src_ip, src_port);
        let val = match map.get(&key, 0) {
            Ok(v) => v,
            Err(_) => {
                debug!(?src_ip, src_port, "SYN v6 map miss - no entry");
                return None;
            }
        };

        let stored_port = u16::from_be(val.src_port);
        if stored_port != src_port {
            warn!(
                ?src_ip,
                src_port,
                stored_port,
                "BPF v6 map port mismatch - possible hash collision, ignoring"
            );
            return None;
        }

        if let Some(current_tick) = self.read_current_tick() {
            if is_stale(val.tick, current_tick, self.syn_map_max_entries) {
                warn!(
                    ?src_ip,
                    src_port,
                    stored_tick = val.tick,
                    current_tick,
                    "SYN v6 map entry is stale - discarding"
                );
                return None;
            }
        }

        Some(val)
    }

    /// Look up the TCP SYN data for an IPv4 client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if:
    /// - the SYN was not captured (program just started, map entry evicted), or
    /// - the entry is stale (more than 2x `syn_map_max_entries` SYNs have arrived since capture).
    pub fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<SynRawDataV4> {
        let syn_map = self.syn_map_v4()?;
        let map = HashMap::<_, u64, SynRawDataV4>::try_from(syn_map).ok()?;

        let key = make_bpf_key_v4(src_ip, src_port);
        let val = match map.get(&key, 0) {
            Ok(v) => v,
            Err(_) => {
                debug!(?src_ip, src_port, "SYN map miss - no entry (keep-alive or not captured)");
                return None;
            }
        };

        // Verify src_port matches to detect map key collisions.
        let stored_port = u16::from_be(val.src_port);
        if stored_port != src_port {
            warn!(
                ?src_ip,
                src_port, stored_port, "BPF map port mismatch - possible hash collision, ignoring"
            );
            return None;
        }

        if let Some(current_tick) = self.read_current_tick() {
            if is_stale(val.tick, current_tick, self.syn_map_max_entries) {
                warn!(
                    ?src_ip,
                    src_port,
                    stored_tick = val.tick,
                    current_tick,
                    "SYN map entry is stale - discarding"
                );
                return None;
            }
        }

        Some(val)
    }
}
