use huginn_ebpf::pin;
use huginn_ebpf_agent::healthchecks::REQUIRED_PINS;

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
