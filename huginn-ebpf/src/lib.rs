#![cfg(target_os = "linux")]
// Unsafe only in types.rs (`unsafe impl aya::Pod`).
#![deny(unsafe_code)]

pub mod config;
pub mod error;
pub mod log_level;
pub mod pin;
pub mod probe;
pub mod types;

pub use config::{CaptureBackend, XdpAttachMode};
pub use error::EbpfError;
pub use log_level::EbpfLogLevel;
pub use probe::{
    is_stale, syn_captured_count_from_path, syn_captured_v6_count_from_path,
    syn_insert_failures_count_from_path, syn_insert_failures_v6_count_from_path,
    syn_malformed_count_from_path, syn_malformed_v6_count_from_path, EbpfLogPoller, EbpfProbe,
    DEFAULT_SYN_MAP_MAX_ENTRIES,
};
pub use types::{parse_syn_v4, parse_syn_v6, quirk_bits, SynRawDataV4, SynRawDataV6};
