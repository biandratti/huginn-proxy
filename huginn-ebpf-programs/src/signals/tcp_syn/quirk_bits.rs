// Quirk computation now lives in huginn-ebpf-common so it can be tested on host.
// Re-export under the original names so call sites in handler.rs are unchanged.
pub use huginn_ebpf_common::quirk_bits::{compute_v4 as compute_quirks_v4, compute_v6 as compute_quirks_v6};
