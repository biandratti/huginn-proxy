use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray};
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use aya_log::EbpfLogger;
use log::Log;
use tracing::{debug, info, warn};

use crate::pin;
use crate::types::{SynRawDataV4, SynRawDataV6};
use crate::CaptureBackend;
use crate::EbpfError;
use crate::EbpfLogLevel;
use crate::XdpAttachMode;

/// Raw bytes of the compiled BPF object (XDP + TC programs), embedded at compile time.
/// `include_bytes_aligned!` ensures 8-byte alignment required by aya's ELF parser.
/// The path is set by `build.rs` via `cargo:rustc-env=BPF_OBJECT_PATH`.
static BPF_OBJECT_BYTES: &[u8] = aya::include_bytes_aligned!(env!("BPF_OBJECT_PATH"));

/// Default max entries for the TCP SYN LRU map when not overridden by the agent.
/// Must match huginn-ebpf-programs's TCP_SYN_MAP_V4_MAX_ENTRIES (ELF default).
pub const DEFAULT_SYN_MAP_MAX_ENTRIES: u32 = 8192;

enum ProbeInner {
    /// Used by `huginn-ebpf-agent`: owns the BPF object and the attached capture program (XDP or TC).
    /// Dropping detaches the program from the interface.
    Embedded { ebpf: Ebpf },
    /// Used by `huginn-proxy`: reads maps pinned by the agent.
    Pinned(Box<PinnedMaps>),
}

/// Maps opened from the agent's pins for the proxy (read-only) side.
///
/// The agent pins all of these in [`EbpfProbe::pin_maps`], so `from_pinned` opens every one and
/// fails if any is missing.
struct PinnedMaps {
    syn_map_v4: Map,
    syn_map_v6: Map,
    counter: Map,
    insert_failures_v4: Map,
    insert_failures_v6: Map,
    captured_v4: Map,
    captured_v6: Map,
    malformed_v4: Map,
    malformed_v6: Map,
}

/// Manages eBPF TCP SYN capture and map lookups.
///
/// - The **agent** calls [`EbpfProbe::new`] to load the capture program and own the maps.
/// - The **proxy** calls [`EbpfProbe::from_pinned`] to read maps pinned by the agent.
///
/// Both code paths store the SYN map capacity (`syn_map_max_entries`); the proxy uses it
/// for stale detection in [`lookup`](Self::lookup) (entry is stale if age > 2× that value).
pub struct EbpfProbe {
    inner: ProbeInner,
    interface: String,
    syn_map_max_entries: u32,
    log_level: EbpfLogLevel,
}

/// Drain handle for eBPF debug logs, produced by [`EbpfProbe::take_debug_log_poller`].
///
/// `aya-log` does not spawn its own polling task: the ring buffer must be drained by the
/// caller. This wraps the [`aya_log::EbpfLogger`] and exposes the file descriptor (via [`AsFd`] /
/// [`AsRawFd`]) plus [`flush`](Self::flush), so the owner (the agent, which has a Tokio runtime)
/// can register it with `tokio::io::unix::AsyncFd` and flush whenever the fd becomes readable.
pub struct EbpfLogPoller {
    inner: EbpfLogger<&'static dyn Log>,
}

impl EbpfLogPoller {
    /// Drain all pending records from the eBPF log ring buffer, forwarding them to the `log`
    /// facade (bridged to `tracing` by the agent's subscriber). Call after the fd reports readable.
    pub fn flush(&mut self) {
        self.inner.flush();
    }
}

impl AsFd for EbpfLogPoller {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for EbpfLogPoller {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_fd().as_raw_fd()
    }
}

impl EbpfProbe {
    /// Load and attach the BPF capture program (XDP or TC) to the given network interface.
    ///
    /// # Parameters
    /// - `interface`: network interface name (e.g., `"eth0"`)
    /// - `dst_ip_v4`: proxy IPv4 listen IP. `0.0.0.0` disables the IPv4 destination filter.
    /// - `dst_ip_v6`: proxy IPv6 listen IP. `::` disables the IPv6 destination filter.
    /// - `dst_port`: proxy listen port. Always active as a filter.
    /// - `syn_map_max_entries`: capacity of the LRU map (default 8192).
    /// - `capture`: [`CaptureBackend::Xdp`] (driver/generic XDP) or [`CaptureBackend::Tc`]
    ///   (clsact ingress; required on VLAN/bond interfaces where generic XDP drops GRO-merged
    ///   data packets).
    /// - `log_level`: verbosity of the in-kernel `aya-log` datapath logging. Patched into the
    ///   program's `log_level` global so the pipelines emit only records at or above it (`debug!`
    ///   on capture, `warn!` on map-insert failure). [`EbpfLogLevel::Off`] (the default) means the
    ///   logging code is compiled in but never executed, so the production hot path pays nothing.
    ///   When non-off, drain the records via [`take_debug_log_poller`](Self::take_debug_log_poller).
    ///
    /// All dst values are patched into the program's `.rodata` via `EbpfLoader::override_global`
    /// before the kernel loads the program. Both hooks share the same `.rodata` globals and maps
    /// in the single embedded ELF.
    pub fn new(
        interface: &str,
        dst_ip_v4: Ipv4Addr,
        dst_ip_v6: Ipv6Addr,
        dst_port: u16,
        syn_map_max_entries: u32,
        capture: CaptureBackend,
        log_level: EbpfLogLevel,
    ) -> Result<Self, EbpfError> {
        // The BPF program compares ip->daddr and tcp->dest (both network-byte-order fields)
        // against these globals. On a little-endian CPU, network-order bytes [a,b,c,d] in the
        // packet are read as u32::from_ne_bytes([a,b,c,d]). We replicate the same encoding here
        // so the comparison in the BPF program works correctly.
        //
        // 0.0.0.0 → bpf_dst_ip = 0 → BPF program skips the IPv4 destination check.
        let bpf_dst_ip: u32 = if dst_ip_v4.is_unspecified() {
            0
        } else {
            u32::from_ne_bytes(dst_ip_v4.octets())
        };

        // :: → all-zero bytes → XDP skips the IPv6 destination check.
        let bpf_dst_ip_v6: [u8; 16] = dst_ip_v6.octets();

        // tcp->dest in network byte order as read by LE CPU = port.to_be()
        let bpf_dst_port: u16 = dst_port.to_be();

        // 0 = logging off (default); higher = more verbose (log::LevelFilter encoding). The
        // capture pipelines only emit records at or above this level.
        let bpf_log_level: u8 = log_level.as_u8();

        let mut ebpf = EbpfLoader::new()
            .override_global("dst_ip_v4", &bpf_dst_ip, false)
            .override_global("dst_ip_v6", &bpf_dst_ip_v6, false)
            .override_global("dst_port", &bpf_dst_port, false)
            .override_global("log_level", &bpf_log_level, false)
            .map_max_entries(pin::SYN_MAP_V4_NAME, syn_map_max_entries)
            .map_max_entries(pin::SYN_MAP_V6_NAME, syn_map_max_entries)
            .load(BPF_OBJECT_BYTES)
            .map_err(EbpfError::Load)?;

        let mode_str = match capture {
            CaptureBackend::Xdp(xdp_mode) => attach_xdp(&mut ebpf, interface, xdp_mode)?,
            CaptureBackend::Tc => attach_tc(&mut ebpf, interface)?,
        };

        let filter_ip_v4 = if dst_ip_v4.is_unspecified() {
            "any".to_string()
        } else {
            dst_ip_v4.to_string()
        };
        let filter_ip_v6 = if dst_ip_v6.is_unspecified() {
            "any".to_string()
        } else {
            dst_ip_v6.to_string()
        };
        info!(
            interface,
            filter_ip_v4,
            filter_ip_v6,
            dst_port,
            mode = mode_str,
            "eBPF TCP SYN fingerprinting attached"
        );

        Ok(Self {
            inner: ProbeInner::Embedded { ebpf },
            interface: interface.to_string(),
            syn_map_max_entries,
            log_level,
        })
    }

    /// Open previously pinned BPF maps created by the eBPF agent.
    ///
    /// The agent must have already pinned `tcp_syn_map_v4`, `tcp_syn_map_v6`, `syn_counter`,
    /// and `syn_insert_failures` under `base_path` (default: `/sys/fs/bpf/huginn/`).
    ///
    /// `syn_map_max_entries` must match the value the agent used when loading the program
    /// (e.g. `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`); it is used for stale entry detection.
    /// This constructor does not load or attach any XDP program, the agent owns that lifecycle.
    pub fn from_pinned(base_path: &str, syn_map_max_entries: u32) -> Result<Self, EbpfError> {
        let syn_data = open_pinned_map(pin::syn_map_v4_path(base_path))?;
        let syn_data_v6 = open_pinned_map(pin::syn_map_v6_path(base_path))?;
        let counter_data = open_pinned_map(pin::counter_path(base_path))?;
        let insert_failures_v4 = open_pinned_map(pin::insert_failures_v4_path(base_path))?;
        let insert_failures_v6 = open_pinned_map(pin::insert_failures_v6_path(base_path))?;
        let captured_v4 = open_pinned_map(pin::syn_captured_v4_path(base_path))?;
        let captured_v6 = open_pinned_map(pin::syn_captured_v6_path(base_path))?;
        let malformed_v4 = open_pinned_map(pin::syn_malformed_v4_path(base_path))?;
        let malformed_v6 = open_pinned_map(pin::syn_malformed_v6_path(base_path))?;

        info!(base_path, "eBPF TCP SYN fingerprinting connected to pinned maps");

        Ok(Self {
            inner: ProbeInner::Pinned(Box::new(PinnedMaps {
                syn_map_v4: Map::LruHashMap(syn_data),
                syn_map_v6: Map::LruHashMap(syn_data_v6),
                counter: Map::Array(counter_data),
                insert_failures_v4: Map::PerCpuArray(insert_failures_v4),
                insert_failures_v6: Map::PerCpuArray(insert_failures_v6),
                captured_v4: Map::PerCpuArray(captured_v4),
                captured_v6: Map::PerCpuArray(captured_v6),
                malformed_v4: Map::PerCpuArray(malformed_v4),
                malformed_v6: Map::PerCpuArray(malformed_v6),
            })),
            interface: String::new(),
            syn_map_max_entries,
            log_level: EbpfLogLevel::Off,
        })
    }

    /// Take the eBPF debug-log drain handle, if a non-off log level was set at [`new`](Self::new).
    ///
    /// Returns `Ok(None)` when logging is off or in pinned (proxy) mode. On success the caller owns
    /// an [`EbpfLogPoller`] and is responsible for draining it (e.g. registering its fd with
    /// `tokio::io::unix::AsyncFd` and calling [`EbpfLogPoller::flush`] on readability). This takes
    /// the `AYA_LOGS` ring-buffer map out of the loaded object, so it may only be called once.
    pub fn take_debug_log_poller(&mut self) -> Result<Option<EbpfLogPoller>, EbpfError> {
        if self.log_level == EbpfLogLevel::Off {
            return Ok(None);
        }
        match &mut self.inner {
            ProbeInner::Embedded { ebpf } => {
                let inner = EbpfLogger::init(ebpf).map_err(EbpfError::LogInit)?;
                Ok(Some(EbpfLogPoller { inner }))
            }
            ProbeInner::Pinned(_) => Ok(None),
        }
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
            ProbeInner::Pinned(_) => return Ok(()),
        };

        let syn_path_v4 = pin::syn_map_v4_path(base_path);
        let syn_path_v6 = pin::syn_map_v6_path(base_path);
        let counter_path = pin::counter_path(base_path);
        let insert_failures_v4_path = pin::insert_failures_v4_path(base_path);
        let syn_captured_v4_path = pin::syn_captured_v4_path(base_path);
        let syn_malformed_v4_path = pin::syn_malformed_v4_path(base_path);
        let insert_failures_v6_path = pin::insert_failures_v6_path(base_path);
        let syn_captured_v6_path = pin::syn_captured_v6_path(base_path);
        let syn_malformed_v6_path = pin::syn_malformed_v6_path(base_path);

        // Remove stale pins from a previous agent instance.
        let _ = std::fs::remove_file(&syn_path_v4);
        let _ = std::fs::remove_file(&syn_path_v6);
        let _ = std::fs::remove_file(&counter_path);
        let _ = std::fs::remove_file(&insert_failures_v4_path);
        let _ = std::fs::remove_file(&syn_captured_v4_path);
        let _ = std::fs::remove_file(&syn_malformed_v4_path);
        let _ = std::fs::remove_file(&insert_failures_v6_path);
        let _ = std::fs::remove_file(&syn_captured_v6_path);
        let _ = std::fs::remove_file(&syn_malformed_v6_path);

        let syn_map_v4 = ebpf
            .map_mut(pin::SYN_MAP_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_map_v4
            .pin(&syn_path_v4)
            .map_err(|e| EbpfError::Pin { name: pin::SYN_MAP_V4_NAME.to_string(), source: e })?;

        let syn_map_v6 = ebpf
            .map_mut(pin::SYN_MAP_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_map_v6
            .pin(&syn_path_v6)
            .map_err(|e| EbpfError::Pin { name: pin::SYN_MAP_V6_NAME.to_string(), source: e })?;

        let counter = ebpf
            .map_mut(pin::COUNTER_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        counter
            .pin(&counter_path)
            .map_err(|e| EbpfError::Pin { name: pin::COUNTER_NAME.to_string(), source: e })?;

        let insert_failures_v4 = ebpf
            .map_mut(pin::SYN_INSERT_FAILURES_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        insert_failures_v4
            .pin(&insert_failures_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_INSERT_FAILURES_V4_NAME.to_string(),
                source: e,
            })?;

        let syn_captured_v4 = ebpf
            .map_mut(pin::SYN_CAPTURED_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_captured_v4
            .pin(&syn_captured_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_CAPTURED_V4_NAME.to_string(),
                source: e,
            })?;

        let syn_malformed_v4 = ebpf
            .map_mut(pin::SYN_MALFORMED_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_malformed_v4
            .pin(&syn_malformed_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_MALFORMED_V4_NAME.to_string(),
                source: e,
            })?;

        let insert_failures_v6 = ebpf
            .map_mut(pin::SYN_INSERT_FAILURES_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        insert_failures_v6
            .pin(&insert_failures_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_INSERT_FAILURES_V6_NAME.to_string(),
                source: e,
            })?;

        let syn_captured_v6 = ebpf
            .map_mut(pin::SYN_CAPTURED_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_captured_v6
            .pin(&syn_captured_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_CAPTURED_V6_NAME.to_string(),
                source: e,
            })?;

        let syn_malformed_v6 = ebpf
            .map_mut(pin::SYN_MALFORMED_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_malformed_v6
            .pin(&syn_malformed_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_MALFORMED_V6_NAME.to_string(),
                source: e,
            })?;

        // BPF_OBJ_GET checks inode permissions (MAY_READ | MAY_WRITE).
        // Pin files are created as 0600 root:root, make them accessible
        // to the non-root proxy process.
        let open_mode = std::fs::Permissions::from_mode(0o666);
        let _ = std::fs::set_permissions(&syn_path_v4, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_path_v6, open_mode.clone());
        let _ = std::fs::set_permissions(&counter_path, open_mode.clone());
        let _ = std::fs::set_permissions(&insert_failures_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_captured_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_malformed_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&insert_failures_v6_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_captured_v6_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_malformed_v6_path, open_mode);

        info!(base_path, "BPF maps pinned");
        Ok(())
    }

    /// Remove pinned map files. Called during agent shutdown for clean teardown.
    pub fn unpin_maps(base_path: &str) {
        let syn_path_v4 = pin::syn_map_v4_path(base_path);
        let syn_path_v6 = pin::syn_map_v6_path(base_path);
        let counter_path = pin::counter_path(base_path);
        let insert_failures_v4_path = pin::insert_failures_v4_path(base_path);
        let syn_captured_v4_path = pin::syn_captured_v4_path(base_path);
        let syn_malformed_v4_path = pin::syn_malformed_v4_path(base_path);
        let insert_failures_v6_path = pin::insert_failures_v6_path(base_path);
        let syn_captured_v6_path = pin::syn_captured_v6_path(base_path);
        let syn_malformed_v6_path = pin::syn_malformed_v6_path(base_path);
        let _ = std::fs::remove_file(&syn_path_v4);
        let _ = std::fs::remove_file(&syn_path_v6);
        let _ = std::fs::remove_file(&counter_path);
        let _ = std::fs::remove_file(&insert_failures_v4_path);
        let _ = std::fs::remove_file(&syn_captured_v4_path);
        let _ = std::fs::remove_file(&syn_malformed_v4_path);
        let _ = std::fs::remove_file(&insert_failures_v6_path);
        let _ = std::fs::remove_file(&syn_captured_v6_path);
        let _ = std::fs::remove_file(&syn_malformed_v6_path);
        info!(base_path, "BPF map pins removed");
    }

    /// Look up the TCP SYN data for an IPv6 client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if:
    /// - the SYN was not captured (program just started, map entry evicted), or
    /// - the entry is stale (more than 2× `syn_map_max_entries` SYNs have arrived since capture).
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
                    "SYN v6 map entry is stale - discarding"
                );
                return None;
            }
        }

        Some(val)
    }

    /// Look up the TCP SYN data for a client connection.
    ///
    /// Should be called immediately after `TcpStream::accept()` while the BPF
    /// map entry is still fresh. Returns `None` if:
    /// - the SYN was not captured (program just started, map entry evicted), or
    /// - the entry is stale (more than 2× `syn_map_max_entries` SYNs have arrived since capture).
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

    fn syn_map_v4(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_MAP_V4_NAME),
            ProbeInner::Pinned(p) => Some(&p.syn_map_v4),
        }
    }

    fn syn_map_v6(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_MAP_V6_NAME),
            ProbeInner::Pinned(p) => Some(&p.syn_map_v6),
        }
    }

    fn counter_map(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::COUNTER_NAME),
            ProbeInner::Pinned(p) => Some(&p.counter),
        }
    }

    /// Read the current value of the global SYN counter from the `syn_counter` BPF map.
    fn read_current_tick(&self) -> Option<u64> {
        read_array_counter(self.counter_map()?)
    }

    /// Read a single-slot `PerCpuArray<u64>` counter map (summed across CPUs), working in both
    /// `Embedded` and `Pinned` modes.
    ///
    /// `name` selects the map by name in embedded mode; `pick` selects the pinned map in pinned
    /// mode. Returns `None` only if the embedded map is absent or cannot be read as a
    /// `PerCpuArray<u64>`.
    fn counter_from(&self, name: &str, pick: impl Fn(&PinnedMaps) -> &Map) -> Option<u64> {
        let map = match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(name)?,
            ProbeInner::Pinned(p) => pick(p),
        };
        read_percpu_counter(map)
    }

    /// Number of IPv4 TCP SYN map insert failures (e.g. LRU full).
    /// Exposed as `tcp_syn_insert_failures_total{family="ipv4"}`.
    pub fn syn_insert_failures_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_INSERT_FAILURES_V4_NAME, |p| &p.insert_failures_v4)
    }

    /// Number of IPv6 TCP SYN map insert failures.
    pub fn syn_insert_failures_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_INSERT_FAILURES_V6_NAME, |p| &p.insert_failures_v6)
    }

    /// Number of successfully captured IPv4 TCP SYN signatures.
    pub fn syn_captured_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_CAPTURED_V4_NAME, |p| &p.captured_v4)
    }

    /// Number of successfully captured IPv6 TCP SYN signatures.
    pub fn syn_captured_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_CAPTURED_V6_NAME, |p| &p.captured_v6)
    }

    /// Number of malformed IPv4 TCP packets (e.g. doff too short) that matched the dst filter.
    pub fn syn_malformed_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_MALFORMED_V4_NAME, |p| &p.malformed_v4)
    }

    /// Number of malformed IPv6 TCP packets that matched the dst filter.
    pub fn syn_malformed_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_MALFORMED_V6_NAME, |p| &p.malformed_v6)
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Open a pinned map by path, mapping open failures to [`EbpfError::FromPin`].
fn open_pinned_map(path: PathBuf) -> Result<MapData, EbpfError> {
    MapData::from_pin(&path)
        .map_err(|e| EbpfError::FromPin { path: path.display().to_string(), source: e })
}

/// Read slot 0 of a single-entry `Array<u64>` counter map (used for the global tick).
fn read_array_counter(map: &Map) -> Option<u64> {
    let array = Array::<_, u64>::try_from(map).ok()?;
    array.get(&0, 0).ok()
}

/// Read slot 0 of a single-entry `PerCpuArray<u64>` counter map, summing the per-CPU values.
///
/// The kernel increments a per-CPU slot (race-free); the meaningful total is the sum across CPUs.
fn read_percpu_counter(map: &Map) -> Option<u64> {
    let array = PerCpuArray::<_, u64>::try_from(map).ok()?;
    let per_cpu = array.get(&0, 0).ok()?;
    Some(per_cpu.iter().fold(0u64, |acc, &v| acc.wrapping_add(v)))
}

/// Load and attach the XDP program (`huginn_xdp_syn`). Returns the mode label for logging.
fn attach_xdp(
    ebpf: &mut Ebpf,
    interface: &str,
    xdp_mode: XdpAttachMode,
) -> Result<&'static str, EbpfError> {
    let program: &mut Xdp = ebpf
        .program_mut("huginn_xdp_syn")
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::ProgramType)?;

    program.load().map_err(EbpfError::ProgramLoad)?;

    let (aya_mode, mode_str) = match xdp_mode {
        XdpAttachMode::Skb => (XdpMode::Skb, "xdp-skb"),
        XdpAttachMode::Native => (XdpMode::Driver, "xdp-native"),
    };
    info!(interface, mode = mode_str, "eBPF XDP attaching");
    program
        .attach(interface, aya_mode)
        .map_err(EbpfError::Attach)?;
    Ok(mode_str)
}

/// Load and attach the TC clsact ingress classifier (`huginn_tc_syn`). Returns the mode label.
///
/// A `clsact` qdisc must exist before attaching an ingress classifier. `qdisc_add_clsact` is
/// idempotent at the netlink layer (a pre-existing qdisc returns `EEXIST`), so a non-fatal error
/// here is logged and ignored: a leftover qdisc from a previous run is harmless and reused.
fn attach_tc(ebpf: &mut Ebpf, interface: &str) -> Result<&'static str, EbpfError> {
    if let Err(e) = tc::qdisc_add_clsact(interface) {
        warn!(interface, error = %e, "clsact qdisc add returned an error (continuing; likely already present)");
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut("huginn_tc_syn")
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::ProgramType)?;

    program.load().map_err(EbpfError::ProgramLoad)?;

    info!(interface, mode = "tc", "eBPF TC clsact ingress attaching");
    program
        .attach(interface, TcAttachType::Ingress)
        .map_err(EbpfError::Attach)?;
    Ok("tc")
}

/// Read the `syn_insert_failures_v4` counter from a pinned map at `base_path`.
///
/// Used by the agent's metrics server without sharing the probe (avoids `Send` on `EbpfProbe`).
/// Returns `None` if the map cannot be opened or read.
pub fn syn_insert_failures_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::insert_failures_v4_path(base_path))
}

/// Read the `syn_captured_v4` counter from a pinned map at `base_path`.
pub fn syn_captured_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_captured_v4_path(base_path))
}

/// Read the `syn_malformed_v4` counter from a pinned map at `base_path`.
pub fn syn_malformed_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_malformed_v4_path(base_path))
}

/// Read the `syn_insert_failures_v6` counter from a pinned map at `base_path`.
pub fn syn_insert_failures_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::insert_failures_v6_path(base_path))
}

/// Read the `syn_captured_v6` counter from a pinned map at `base_path`.
pub fn syn_captured_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_captured_v6_path(base_path))
}

/// Read the `syn_malformed_v6` counter from a pinned map at `base_path`.
pub fn syn_malformed_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_malformed_v6_path(base_path))
}

fn read_percpu_counter_from_path(path: impl AsRef<std::path::Path>) -> Option<u64> {
    let data = MapData::from_pin(path.as_ref()).ok()?;
    read_percpu_counter(&Map::PerCpuArray(data))
}

/// Build the BPF map lookup key matching the BPF program's `make_key_v4()` (IPv4).
///
/// The BPF program: `((__u64)ip->saddr << 16) | tcp->source`
/// Both `ip->saddr` and `tcp->source` are in network byte order as seen by
/// the LE CPU (i.e., the raw BE bytes interpreted as a LE integer value).
///
/// From Rust's `Ipv4Addr` and host-byte-order port, we reconstruct the same key.
pub fn make_bpf_key_v4(src_ip: Ipv4Addr, src_port: u16) -> u64 {
    // ip->saddr: network-order bytes [a,b,c,d] read by LE CPU = u32::from_ne_bytes([a,b,c,d])
    let ip_ne = u32::from_ne_bytes(src_ip.octets());
    // tcp->source: network-order port bytes [hi,lo] read by LE CPU
    let port_ne = u16::from_ne_bytes(src_port.to_be_bytes());
    (u64::from(ip_ne) << 16) | u64::from(port_ne)
}

/// Build the BPF map lookup key matching the BPF program's `make_key_v6()` (IPv6).
///
/// Layout: 16 bytes of IPv6 address (network byte order) followed by 2 bytes of
/// TCP source port (network byte order). Matches the kernel-side `make_key_v6` in
/// `huginn-ebpf-common`.
pub fn make_bpf_key_v6(src_ip: Ipv6Addr, src_port: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..16].copy_from_slice(&src_ip.octets());
    let port_be = src_port.to_be_bytes();
    key[16] = port_be[0];
    key[17] = port_be[1];
    key
}
