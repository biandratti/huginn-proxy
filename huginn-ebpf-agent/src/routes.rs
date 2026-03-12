use std::path::Path;

use huginn_ebpf::pin;

/// True if all BPF map pins exist under `base` (used by ready_check_response).
pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    base.join(pin::SYN_MAP_V4_NAME).exists()
        && base.join(pin::COUNTER_NAME).exists()
        && base.join(pin::SYN_INSERT_FAILURES_NAME).exists()
}
