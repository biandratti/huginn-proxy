//! Every symbol the loader patches or pins *by name* must exist in the BPF object.
//!
//! `override_global(.., false)` and `map_pin_path` silently do nothing on a name that does not
//! resolve, so a renamed or dead-stripped global leaves the rate limiter dead while the config
//! still reports it on. `must_exist = true` would make that a load error, but a dead agent pins
//! no maps at all - so the loader stays permissive and this catches it at build time.
//!
//! `aya` resolves these names at load, so they are in the ELF string tables: a byte search is
//! enough.

use huginn_ebpf::pin;

/// The compiled object `build.rs` embeds.
fn bpf_object() -> Vec<u8> {
    let path = env!("BPF_OBJECT_PATH");
    std::fs::read(path).unwrap_or_else(|e| panic!("could not read the BPF object at {path}: {e}"))
}

fn contains_symbol(object: &[u8], needle: &str) -> bool {
    object
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Every name passed to `override_global` in `EbpfProbe::new`.
const PATCHED_GLOBALS: &[&str] = &[
    "dst_ip_v4",
    "dst_ip_v6",
    "dst_port",
    "log_level",
    "syn_rate_enabled",
    "syn_rate_threshold",
    "syn_rate_window_ns",
];

#[test]
fn every_patched_global_exists_in_the_bpf_object() {
    let object = bpf_object();
    for name in PATCHED_GLOBALS {
        assert!(
            contains_symbol(&object, name),
            "global '{name}' is patched by EbpfProbe::new but is missing from the BPF object; \
             the patch is skipped silently and the program keeps its compiled-in default"
        );
    }
}

#[test]
fn every_pinned_map_exists_in_the_bpf_object() {
    let object = bpf_object();
    for name in pin::ALL_NAMES {
        assert!(
            contains_symbol(&object, name),
            "map '{name}' is in pin::ALL_NAMES but missing from the BPF object, so it would never \
             be pinned; if it is also in the agent's REQUIRED_PINS, /ready never turns ready"
        );
    }
}

#[test]
fn the_rate_limit_sketch_maps_exist_but_are_not_pinned() {
    // Out of the pin set on purpose: pinning would persist per-CPU state across reloads.
    let object = bpf_object();
    for name in ["syn_rate_sketch_v4", "syn_rate_sketch_v6"] {
        assert!(contains_symbol(&object, name), "sketch map '{name}' is missing from the object");
        assert!(!pin::ALL_NAMES.contains(&name), "sketch map '{name}' must not be pinned");
    }
}
