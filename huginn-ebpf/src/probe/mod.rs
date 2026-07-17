use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};

use aya::maps::Map;
use aya::{Ebpf, EbpfLoader};
use aya_log::EbpfLogger;
use log::Log;
use tracing::info;

use crate::pin;
use crate::CaptureBackend;
use crate::EbpfError;
use crate::EbpfLogLevel;

mod attach;
mod counters;
mod keys;
mod lookup;
mod maps;

pub use counters::{
    is_stale, syn_captured_count_from_path, syn_captured_v6_count_from_path,
    syn_insert_failures_count_from_path, syn_insert_failures_v6_count_from_path,
    syn_malformed_count_from_path, syn_malformed_v6_count_from_path,
};
pub use keys::{make_bpf_key_v4, make_bpf_key_v6};

/// Raw bytes of the compiled BPF object (XDP + TC programs), embedded at compile time.
/// `include_bytes_aligned!` ensures 8-byte alignment required by aya's ELF parser.
/// The path is set by `build.rs` via `cargo:rustc-env=BPF_OBJECT_PATH`.
static BPF_OBJECT_BYTES: &[u8] = aya::include_bytes_aligned!(env!("BPF_OBJECT_PATH"));

/// Default max entries for the TCP SYN LRU map when not overridden by the agent.
/// Must match huginn-ebpf-programs's TCP_SYN_MAP_V4_MAX_ENTRIES (ELF default).
pub const DEFAULT_SYN_MAP_MAX_ENTRIES: u32 = 8192;

enum ProbeInner {
    /// Used by `huginn-ebpf-agent`: owns the BPF object and the attached capture program.
    /// Dropping detaches the program from the interface.
    Embedded { ebpf: Ebpf },
    /// Used by `huginn-proxy`: reads maps pinned by the agent.
    Pinned(Box<PinnedMaps>),
}

/// Maps opened from the agent's pins for the proxy side.
struct PinnedMaps {
    ipv4: PinnedFamilyMaps,
    ipv6: PinnedFamilyMaps,
    counter: Map,
}

/// Pinned SYN data and telemetry maps belonging to one IP family.
struct PinnedFamilyMaps {
    syn: Map,
    id: u32,
    insert_failures: Map,
    captured: Map,
    malformed: Map,
}

/// Kernel identities of the IPv4 and IPv6 TCP SYN maps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedMapIds {
    pub ipv4: u32,
    pub ipv6: u32,
}

/// Agent loads and attaches; proxy reads pinned maps. Stale threshold is 2x `syn_map_max_entries`.
pub struct EbpfProbe {
    inner: ProbeInner,
    interface: String,
    syn_map_max_entries: u32,
    log_level: EbpfLogLevel,
}

/// Ring-buffer drain handle for `aya-log`. Caller must poll the fd and call [`flush`](Self::flush).
pub struct EbpfLogPoller {
    inner: EbpfLogger<&'static dyn Log>,
}

impl EbpfLogPoller {
    /// Drain pending records from the eBPF log ring buffer.
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
    /// - `pin_base`: bpffs directory where maps are pinned (e.g. `/sys/fs/bpf/huginn`). Reuses
    ///   existing pins on restart; drops them first when `syn_map_max_entries` changed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interface: &str,
        dst_ip_v4: Ipv4Addr,
        dst_ip_v6: Ipv6Addr,
        dst_port: u16,
        syn_map_max_entries: u32,
        capture: CaptureBackend,
        log_level: EbpfLogLevel,
        pin_base: &str,
    ) -> Result<Self, EbpfError> {
        // The BPF program compares ip->daddr and tcp->dest (both network-byte-order fields)
        // against these globals. On a little-endian CPU, network-order bytes [a,b,c,d] in the
        // packet are read as u32::from_ne_bytes([a,b,c,d]). We replicate the same encoding here
        // so the comparison in the BPF program works correctly.
        //
        // 0.0.0.0 -> bpf_dst_ip = 0 -> BPF program skips the IPv4 destination check.
        let bpf_dst_ip: u32 = if dst_ip_v4.is_unspecified() {
            0
        } else {
            u32::from_ne_bytes(dst_ip_v4.octets())
        };

        // :: -> all-zero bytes -> XDP skips the IPv6 destination check.
        let bpf_dst_ip_v6: [u8; 16] = dst_ip_v6.octets();

        // tcp->dest in network byte order as read by LE CPU = port.to_be()
        let bpf_dst_port: u16 = dst_port.to_be();

        // 0 = logging off (default); higher = more verbose (log::LevelFilter encoding).
        let bpf_log_level: u8 = log_level.as_u8();

        // Create the pin directory and drop any pins left over from an
        // incompatible capacity before the loader touches them.
        maps::prepare_pins(pin_base, syn_map_max_entries)?;

        // Reuse existing pins when present so the maps survive agent restarts
        // with the same kernel ids; the loader creates and pins them otherwise.
        let pin_paths: Vec<(&'static str, PathBuf)> = pin::ALL_NAMES
            .iter()
            .map(|&name| (name, Path::new(pin_base).join(name)))
            .collect();

        let mut loader = EbpfLoader::new();
        loader
            .override_global("dst_ip_v4", &bpf_dst_ip, false)
            .override_global("dst_ip_v6", &bpf_dst_ip_v6, false)
            .override_global("dst_port", &bpf_dst_port, false)
            .override_global("log_level", &bpf_log_level, false)
            .map_max_entries(pin::SYN_MAP_V4_NAME, syn_map_max_entries)
            .map_max_entries(pin::SYN_MAP_V6_NAME, syn_map_max_entries);
        for (name, path) in &pin_paths {
            loader.map_pin_path(name, path.as_path());
        }
        let mut ebpf = loader.load(BPF_OBJECT_BYTES).map_err(EbpfError::Load)?;

        // aya creates pins as 0600 root:root; relax them for the proxy process.
        maps::chmod_pins(pin_base);

        let mode_str = match capture {
            CaptureBackend::Xdp(xdp_mode) => attach::attach_xdp(&mut ebpf, interface, xdp_mode)?,
            CaptureBackend::Tc => attach::attach_tc(&mut ebpf, interface)?,
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
    /// The LRU capacity used for stale-entry detection is read from the pinned SYN map itself
    /// (`max_entries`), so it always matches the value the agent created the map with, with no
    /// separate configuration that could drift. This constructor does not load or attach any XDP
    /// program, the agent owns that lifecycle.
    pub fn from_pinned(base_path: &str) -> Result<Self, EbpfError> {
        let syn_path_v4 = pin::syn_map_v4_path(base_path);
        let syn_path_v6 = pin::syn_map_v6_path(base_path);
        let syn_data_v4 = maps::open_pinned_map(syn_path_v4.clone())?;
        let syn_data_v6 = maps::open_pinned_map(syn_path_v6.clone())?;
        let syn_id_v4 = maps::open_map_id(&syn_data_v4, syn_path_v4.clone())?;
        let syn_id_v6 = maps::open_map_id(&syn_data_v6, syn_path_v6)?;
        // Shared LRU capacity: a single value that pairs with the global `syn_counter`
        // for staleness (both families are created equal by the agent, so it is read
        // from either SYN map). Sourced from the kernel rather than a proxy-side env
        // var that could drift from the agent's value. TODO: ....
        let syn_map_max_entries = maps::open_map_max_entries(&syn_data_v4, syn_path_v4)?;
        let counter_data = maps::open_pinned_map(pin::counter_path(base_path))?;
        let insert_failures_v4 = maps::open_pinned_map(pin::insert_failures_v4_path(base_path))?;
        let insert_failures_v6 = maps::open_pinned_map(pin::insert_failures_v6_path(base_path))?;
        let captured_v4 = maps::open_pinned_map(pin::syn_captured_v4_path(base_path))?;
        let captured_v6 = maps::open_pinned_map(pin::syn_captured_v6_path(base_path))?;
        let malformed_v4 = maps::open_pinned_map(pin::syn_malformed_v4_path(base_path))?;
        let malformed_v6 = maps::open_pinned_map(pin::syn_malformed_v6_path(base_path))?;

        info!(base_path, "eBPF TCP SYN fingerprinting connected to pinned maps");

        Ok(Self {
            inner: ProbeInner::Pinned(Box::new(PinnedMaps {
                ipv4: PinnedFamilyMaps {
                    syn: Map::LruHashMap(syn_data_v4),
                    id: syn_id_v4,
                    insert_failures: Map::PerCpuArray(insert_failures_v4),
                    captured: Map::PerCpuArray(captured_v4),
                    malformed: Map::PerCpuArray(malformed_v4),
                },
                ipv6: PinnedFamilyMaps {
                    syn: Map::LruHashMap(syn_data_v6),
                    id: syn_id_v6,
                    insert_failures: Map::PerCpuArray(insert_failures_v6),
                    captured: Map::PerCpuArray(captured_v6),
                    malformed: Map::PerCpuArray(malformed_v6),
                },
                counter: Map::Array(counter_data),
            })),
            interface: String::new(),
            syn_map_max_entries,
            log_level: EbpfLogLevel::Off,
        })
    }

    /// Read the kernel identities currently published at the IPv4 and IPv6 pin paths.
    pub fn pinned_map_ids_from_path(base_path: &str) -> Result<PinnedMapIds, EbpfError> {
        Ok(PinnedMapIds {
            ipv4: maps::pinned_map_id(pin::syn_map_v4_path(base_path))?,
            ipv6: maps::pinned_map_id(pin::syn_map_v6_path(base_path))?,
        })
    }

    /// Return the identities captured when this probe opened the pinned maps.
    pub fn pinned_map_ids(&self) -> Option<PinnedMapIds> {
        match &self.inner {
            ProbeInner::Embedded { .. } => None,
            ProbeInner::Pinned(pinned) => {
                Some(PinnedMapIds { ipv4: pinned.ipv4.id, ipv6: pinned.ipv6.id })
            }
        }
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

    fn syn_map_v4(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_MAP_V4_NAME),
            ProbeInner::Pinned(p) => Some(&p.ipv4.syn),
        }
    }

    fn syn_map_v6(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::SYN_MAP_V6_NAME),
            ProbeInner::Pinned(p) => Some(&p.ipv6.syn),
        }
    }

    fn counter_map(&self) -> Option<&Map> {
        match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(pin::COUNTER_NAME),
            ProbeInner::Pinned(p) => Some(&p.counter),
        }
    }

    fn read_current_tick(&self) -> Option<u64> {
        counters::read_array_counter(self.counter_map()?)
    }

    fn counter_from(&self, name: &str, pick: impl Fn(&PinnedMaps) -> &Map) -> Option<u64> {
        let map = match &self.inner {
            ProbeInner::Embedded { ebpf } => ebpf.map(name)?,
            ProbeInner::Pinned(p) => pick(p),
        };
        counters::read_percpu_counter(map)
    }

    /// Number of IPv4 TCP SYN map insert failures (e.g. LRU full).
    /// Exposed as `tcp_syn_insert_failures_total{family="ipv4"}`.
    pub fn syn_insert_failures_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_INSERT_FAILURES_V4_NAME, |p| &p.ipv4.insert_failures)
    }

    /// Number of IPv6 TCP SYN map insert failures.
    pub fn syn_insert_failures_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_INSERT_FAILURES_V6_NAME, |p| &p.ipv6.insert_failures)
    }

    /// Number of successfully captured IPv4 TCP SYN signatures.
    pub fn syn_captured_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_CAPTURED_V4_NAME, |p| &p.ipv4.captured)
    }

    /// Number of successfully captured IPv6 TCP SYN signatures.
    pub fn syn_captured_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_CAPTURED_V6_NAME, |p| &p.ipv6.captured)
    }

    /// Number of malformed IPv4 TCP packets (e.g. doff too short) that matched the dst filter.
    pub fn syn_malformed_count(&self) -> Option<u64> {
        self.counter_from(pin::SYN_MALFORMED_V4_NAME, |p| &p.ipv4.malformed)
    }

    /// Number of malformed IPv6 TCP packets that matched the dst filter.
    pub fn syn_malformed_count_v6(&self) -> Option<u64> {
        self.counter_from(pin::SYN_MALFORMED_V6_NAME, |p| &p.ipv6.malformed)
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}
