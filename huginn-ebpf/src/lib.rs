#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod log_level;
pub mod pin;
pub mod probe;
pub mod types;

pub use config::{CaptureBackend, CaptureMode, SynRateLimit, XdpAttachMode};
pub use error::EbpfError;
pub use log_level::EbpfLogLevel;
pub use probe::{
    bump_capture_generation, is_stale, new_agent_boot_id, read_capture_state,
    syn_captured_v4_count_from_path, syn_captured_v6_count_from_path,
    syn_insert_failures_v4_count_from_path, syn_insert_failures_v6_count_from_path,
    syn_malformed_v4_count_from_path, syn_malformed_v6_count_from_path,
    syn_rate_allowed_v4_count_from_path, syn_rate_allowed_v6_count_from_path,
    syn_rate_skipped_v4_count_from_path, syn_rate_skipped_v6_count_from_path, write_capture_state,
    CaptureState, EbpfLogPoller, EbpfProbe, DEFAULT_SYN_MAP_MAX_ENTRIES,
};
pub use types::{parse_syn_v4, parse_syn_v6, quirk_bits, SynRawDataV4, SynRawDataV6};
