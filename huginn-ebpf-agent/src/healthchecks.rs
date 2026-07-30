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

#[cfg(test)]
mod tests {
    use super::REQUIRED_PINS;
    use huginn_ebpf::pin;

    /// A name the loader never pins can never appear, so `/ready` would stay 503 forever.
    /// Deliberately a subset check: telemetry-only maps are pinned but do not gate readiness.
    #[test]
    fn every_required_pin_is_one_the_loader_actually_pins() {
        for name in REQUIRED_PINS {
            assert!(
                pin::ALL_NAMES.contains(name),
                "/ready requires '{name}', but it is not in pin::ALL_NAMES so the loader never \
                 pins it; readiness would never turn ready"
            );
        }
    }
}
