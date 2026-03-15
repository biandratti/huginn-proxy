use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, EbpfLoader};
use tracing::{debug, info, warn};

use crate::pin;
use crate::types::SynRawData;
use crate::EbpfError;

/// Raw bytes of the compiled XDP BPF object, embedded at compile time.
/// `include_bytes_aligned!` ensures 8-byte alignment required by aya's ELF parser.
static XDP_BPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp.bpf.o"));

/// For dev/diagnostics only (e.g. workspace example `examples/bpf_test`).
pub(crate) fn bpf_object_bytes() -> &'static [u8] {
    XDP_BPF_BYTES
}

/// Default max entries for the TCP SYN LRU map when not overridden by the agent.
/// Must match huginn-ebpf-xdp's TCP_SYN_MAP_V4_MAX_ENTRIES (ELF default).
pub const DEFAULT_SYN_MAP_MAX_ENTRIES: u32 = 8192;

enum ProbeInner {
    /// Used by `huginn-ebpf-agent`: owns the BPF object and XDP program.
    /// Dropping detaches XDP from the interface.
    Embedded { ebpf: Ebpf },
    /// Used by `huginn-proxy`: reads maps pinned by the agent.
    Pinned {
        syn_map: Map,
        counter: Map,
        insert_failures: Map,
    },
}

/// Manages eBPF XDP SYN data lookups.
///
/// - The **agent** calls [`EbpfProbe::new`] to load XDP and own the maps.
/// - The **proxy** calls [`EbpfProbe::from_pinned`] to read maps pinned by the agent.
///
/// Both code paths store the SYN map capacity (`syn_map_max_entries`); the proxy uses it
/// for stale detection in [`lookup`](Self::lookup) (entry is stale if age > 2× that value).
pub struct EbpfProbe {
    inner: ProbeInner,
    interface: String,
    syn_map_max_entries: u32,
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
    ///
    /// `syn_map_max_entries`: capacity of the LRU map (default 8192). Overridden at load
    /// time via `set_max_entries`; also used for stale detection (threshold = 2× this value).
    pub fn new(
        interface: &str,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        syn_map_max_entries: u32,
    ) -> Result<Self, EbpfError> {
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
            .set_max_entries(pin::SYN_MAP_V4_NAME, syn_map_max_entries)
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

        Ok(Self {
            inner: ProbeInner::Embedded { ebpf },
            interface: interface.to_string(),
            syn_map_max_entries,
        })
    }

    /// Open previously pinned BPF maps created by the eBPF agent.
    ///
    /// The agent must have already pinned `tcp_syn_map_v4`, `syn_counter`, and
    /// `syn_insert_failures` under `base_path` (default: `/sys/fs/bpf/huginn/`).
    ///
    /// `syn_map_max_entries` must match the value the agent used when loading the program
    /// (e.g. `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`); it is used for stale entry detection.
    /// This constructor does not load or attach any XDP program — the agent owns that lifecycle.
    pub fn from_pinned(base_path: &str, syn_map_max_entries: u32) -> Result<Self, EbpfError> {
        let syn_map_path = pin::syn_map_v4_path(base_path);
        let counter_path = pin::counter_path(base_path);
        let insert_failures_path = pin::insert_failures_path(base_path);

        let syn_data = MapData::from_pin(&syn_map_path).map_err(|e| EbpfError::FromPin {
            path: syn_map_path.display().to_string(),
            source: e,
        })?;
        let counter_data = MapData::from_pin(&counter_path).map_err(|e| EbpfError::FromPin {
            path: counter_path.display().to_string(),
            source: e,
        })?;
        let insert_failures_data = MapData::from_pin(&insert_failures_path).map_err(|e| {
            EbpfError::FromPin { path: insert_failures_path.display().to_string(), source: e }
        })?;

        info!(base_path, "eBPF TCP SYN fingerprinting connected to pinned maps");

        Ok(Self {
            inner: ProbeInner::Pinned {
                syn_map: Map::LruHashMap(syn_data),
                counter: Map::Array(counter_data),
                insert_failures: Map::Array(insert_failures_data),
            },
            interface: String::new(),
            syn_map_max_entries,
        })
    }

    /// Pin the BPF maps to `base_path` so other processes can open them.
    ///
    /// Creates the directory if it does not exist. Removes stale pins from a
    /// previous run before pinning. Only valid in embedded mode.
    pub fn pin_maps(&mut self, base_path: &str) -> Result<(), EbpfError> {
        let base = Path::new(base_path);
        std::fs::create_dir_all(base)
            .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;
        if let Some(parent) = base.parent() {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;

        let ebpf = match &mut self.inner {
            ProbeInner::Embedded { ebpf } => ebpf,
            ProbeInner::Pinned { .. } => return Ok(()),
        };

        let syn_path = pin::syn_map_v4_path(base_path);
        let counter_path = pin::counter_path(base_path);

        let insert_failures_path = pin::insert_failures_path(base_path);

        // Remove stale pins from a previous agent instance.
        let _ = std::fs::remove_file(&syn_path);
        let _ = std::fs::remove_file(&counter_path);
        let _ = std::fs::remove_file(&insert_failures_path);

        let syn_map = ebpf
            .map_mut(pin::SYN_MAP_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_map
            .pin(&syn_path)
            .map_err(|e| EbpfError::Pin { name: pin::SYN_MAP_V4_NAME.to_string(), source: e })?;

        let counter = ebpf
            .map_mut(pin::COUNTER_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        counter
            .pin(&counter_path)
            .map_err(|e| EbpfError::Pin { name: pin::COUNTER_NAME.to_string(), source: e })?;

        let insert_failures = ebpf
            .map_mut(pin::SYN_INSERT_FAILURES_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        insert_failures
            .pin(&insert_failures_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_INSERT_FAILURES_NAME.to_string(),
                source: e,
            })?;

        // BPF_OBJ_GET checks inode permissions (MAY_READ | MAY_WRITE).
        // Pin files are created as 0600 root:root — make them accessible
        // to the non-root proxy process.
        let open_mode = std::fs::Permissions::from_mode(0o666);
        let _ = std::fs::set_permissions(&syn_path, open_mode.clone());
        let _ = std::fs::set_permissions(&counter_path, open_mode.clone());
        let _ = std::fs::set_permissions(&insert_failures_path, open_mode);

        info!(base_path, "BPF maps pinned");
        Ok(())
    }

    /// Remove pinned map files. Called during agent shutdown for clean teardown.
    pub fn unpin_maps(base_path: &str) {
        let syn_path = pin::syn_map_v4_path(base_path);
        let counter_path = pin::counter_path(base_path);
        let insert_failures_path = pin::insert_failures_path(base_path);
        let _ = std::fs::remove_file(&syn_path);
        let _ = std::fs::remove_file(&counter_path);
        let _ = std::fs::remove_file(&insert_failures_path);
        info!(base_path, "BPF map pins removed");
    }

    /// Look up the TCP SYN data for a client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if:
    /// - the SYN was not captured (program just started, IPv6 client, map entry evicted), or
    /// - the entry is stale (more than 2× `syn_map_max_entries` SYNs have arrived since capture).
    pub fn lookup(&self, src_ip: Ipv4Addr, src_port: u16) -> Option<SynRawData> {
        let syn_map = self.syn_map()?;
        let map = HashMap::<_, u64, SynRawData>::try_from(syn_map).ok()?;

        let key = make_bpf_key(src_ip, src_port);
        let val = match map.get(&key, 0) {
            Ok(v) => v,
            Err(_) => {
                debug!(?src_ip, src_port, "SYN map miss - no entry (keep-alive or not captured)");
                return None;
            }
        };

        // Sanity: verify src_port matches to detect map key collisions.
        let stored_port = u16::from_be(val.src_port);
        if stored_port != src_port {
            warn!(
                ?src_ip,
                src_port, stored_port, "BPF map port mismatch - possible hash collision, ignoring"
            );
            return None;
        }

        // Stale detection: compare stored tick against the current global counter.
        // If many SYNs have arrived since this entry was written, the entry may
        // belong to an earlier connection that reused the same src_ip:src_port.
        // Threshold 2× map size: enough margin for slow HTTP sessions, but discard
        // entries that are likely from a previous connection (port reuse).
        let stale_threshold = u64::from(self.syn_map_max_entries) * 2;
        if let Some(current_tick) = self.read_current_tick() {
            let age = current_tick.saturating_sub(val.tick);
            if age > stale_threshold {
                warn!(
                    ?src_ip,
                    src_port,
                    stored_tick = val.tick,
                    current_tick,
                    age,
                    threshold = stale_threshold,
                    "SYN map entry is stale - discarding"
                );
                return None;
            }
        }

        Some(val)
    }

    fn syn_map(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_MAP_V4_NAME),
            ProbeInner::Pinned { syn_map, .. } => Some(syn_map),
        }
    }

    fn counter_map(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::COUNTER_NAME),
            ProbeInner::Pinned { counter, .. } => Some(counter),
        }
    }

    fn insert_failures_map(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_INSERT_FAILURES_NAME),
            ProbeInner::Pinned { insert_failures, .. } => Some(insert_failures),
        }
    }

    /// Read the current value of the global SYN counter from the `syn_counter` BPF map.
    fn read_current_tick(&self) -> Option<u64> {
        let map = self.counter_map()?;
        let array = Array::<_, u64>::try_from(map).ok()?;
        array.get(&0, 0).ok()
    }

    /// Read the number of TCP SYN map insert failures (e.g. LRU full).
    ///
    /// The XDP program increments this counter when `tcp_syn_map_v4.insert()` fails.
    /// Expose as a metric (e.g. `tcp_syn_insert_failures_total`) for observability.
    pub fn syn_insert_failures_count(&self) -> Option<u64> {
        let map = self.insert_failures_map()?;
        let array = Array::<_, u64>::try_from(map).ok()?;
        array.get(&0, 0).ok()
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Read the `syn_insert_failures` counter from a pinned map at `base_path`.
///
/// Used by the agent's metrics server without sharing the probe (avoids `Send` on `EbpfProbe`).
/// Returns `None` if the map cannot be opened or read.
pub fn syn_insert_failures_count_from_path(base_path: &str) -> Option<u64> {
    let path = pin::insert_failures_path(base_path);
    let data = MapData::from_pin(&path).ok()?;
    let map = Map::Array(data);
    let array = Array::<_, u64>::try_from(map).ok()?;
    array.get(&0, 0).ok()
}

/// Build the BPF map lookup key matching the XDP program's `make_key()`.
///
/// The XDP program: `((__u64)ip->saddr << 16) | tcp->source`
/// Both `ip->saddr` and `tcp->source` are in network byte order as seen by
/// the LE CPU (i.e., the raw BE bytes interpreted as a LE integer value).
///
/// From Rust's `Ipv4Addr` and host-byte-order port, we reconstruct the same key.
///
/// **IPv4 only** - the XDP program filters `ETH_P_IP` and ignores IPv6 packets.
/// IPv6 listen addresses are rejected at startup in `main.rs`.
pub fn make_bpf_key(src_ip: Ipv4Addr, src_port: u16) -> u64 {
    // ip->saddr: network-order bytes [a,b,c,d] read by LE CPU = u32::from_ne_bytes([a,b,c,d])
    let ip_ne = u32::from_ne_bytes(src_ip.octets());
    // tcp->source: network-order port bytes [hi,lo] read by LE CPU
    let port_ne = u16::from_ne_bytes(src_port.to_be_bytes());
    (u64::from(ip_ne) << 16) | u64::from(port_ne)
}
