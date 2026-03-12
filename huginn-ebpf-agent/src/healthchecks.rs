//! Readiness checks: verify BPF map pins exist (used by /ready).
//! Defensive: if something external removes pins at runtime, we report not ready.

use huginn_ebpf::pin;
use std::path::Path;

pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    base.join(pin::SYN_MAP_V4_NAME).exists()
        && base.join(pin::COUNTER_NAME).exists()
        && base.join(pin::SYN_INSERT_FAILURES_NAME).exists()
}
