//! Readiness checks: verify BPF map pins exist (used by /ready).
//! Defensive: if something external removes pins at runtime, we report not ready.

use huginn_ebpf::pin;
use std::path::Path;

const REQUIRED_PINS: &[&str] = &[
    pin::SYN_MAP_V4_NAME,
    pin::SYN_MAP_V6_NAME,
    pin::COUNTER_NAME,
    pin::SYN_INSERT_FAILURES_V4_NAME,
    pin::SYN_INSERT_FAILURES_V6_NAME,
    pin::SYN_CAPTURED_V4_NAME,
    pin::SYN_CAPTURED_V6_NAME,
    pin::SYN_MALFORMED_V4_NAME,
    pin::SYN_MALFORMED_V6_NAME,
];

pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    REQUIRED_PINS.iter().all(|name| base.join(name).exists())
}
