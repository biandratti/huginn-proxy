use huginn_ebpf::is_stale;

#[test]
fn fresh_entry_is_not_stale() {
    // stored and current are the same tick — age = 0
    assert!(!is_stale(100, 100, 8192));
}

#[test]
fn entry_within_threshold_is_not_stale() {
    // age = 2 × 8192 = 16384, exactly at threshold → not stale
    assert!(!is_stale(0, 16384, 8192));
}

#[test]
fn entry_one_over_threshold_is_stale() {
    // age = threshold + 1 → stale
    assert!(is_stale(0, 16385, 8192));
}

#[test]
fn entry_far_over_threshold_is_stale() {
    assert!(is_stale(0, 100_000, 8192));
}

#[test]
fn small_map_threshold_is_respected() {
    // map_max_entries = 1 → threshold = 2
    assert!(!is_stale(0, 2, 1));
    assert!(is_stale(0, 3, 1));
}

#[test]
fn current_tick_behind_stored_saturates_to_zero() {
    // current < stored: saturating_sub gives 0 → age = 0 → not stale
    assert!(!is_stale(500, 100, 8192));
}

#[test]
fn zero_map_entries_threshold_is_zero() {
    // 2 × 0 = 0; any positive age is stale
    assert!(is_stale(0, 1, 0));
    // age = 0 is not stale (not strictly greater)
    assert!(!is_stale(0, 0, 0));
}

#[test]
fn u32_max_entries_does_not_overflow() {
    // threshold = 2 × u32::MAX; saturating_mul must not wrap to a small number.
    let max = u32::MAX;
    let threshold = u64::from(max).saturating_mul(2); // = 8_589_934_590

    // An entry at age = threshold is not stale (boundary).
    assert!(!is_stale(0, threshold, max));
    // An entry at age = threshold + 1 is stale.
    assert!(is_stale(0, threshold.saturating_add(1), max));
    // u64::MAX is well above threshold → stale.
    assert!(is_stale(0, u64::MAX, max));
}
