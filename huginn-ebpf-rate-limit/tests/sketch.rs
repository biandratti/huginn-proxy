use huginn_ebpf_rate_limit::{
    cell_indices, key_v4, key_v6, Sketch, SketchKey, MAX_THRESHOLD, SLOTS, SLOT_LEN,
};

const WINDOW: u64 = 1_000_000_000; // 1s in ns

/// Stands in for the random seed the loader patches in per program load.
const SEED: u64 = 0x5EED_1234_ABCD_9876;

fn key_from_v4(ip: u32) -> SketchKey {
    key_v4(ip, SEED)
}

#[test]
fn allows_up_to_threshold_then_goes_over_limit() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0001);
    let threshold = 5;
    for i in 1..=threshold {
        let over = s.observe_over_limit(key, 0, WINDOW, threshold);
        assert!(!over, "observation {i} should be allowed");
    }
    assert!(
        s.observe_over_limit(key, 0, WINDOW, threshold),
        "6th observation goes over the limit"
    );
    assert!(
        s.observe_over_limit(key, 0, WINDOW, threshold),
        "stays over the limit in this window"
    );
}

#[test]
fn previous_window_carries_over_then_decays() {
    // Sliding window: the previous window's count does not vanish at the boundary. It carries
    // over at full weight when the new window starts and decays linearly to zero by the end.
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0002);
    let threshold = 10;
    for _ in 0..20 {
        s.observe_over_limit(key, 0, WINDOW, threshold);
    }
    assert!(s.observe_over_limit(key, 0, WINDOW, threshold), "over the limit in window 1");

    // Start of window 2: previous window fully weighted, so a boundary-straddling flood stays over.
    assert!(
        s.observe_over_limit(key, WINDOW, WINDOW, threshold),
        "previous window carries over at the boundary"
    );

    // End of window 2: previous window decayed to ~0, so a now-quiet key is allowed again.
    assert!(
        !s.observe_over_limit(key, WINDOW.saturating_mul(2).saturating_sub(1), WINDOW, threshold),
        "previous window decays out by the end, so a quiet new window is allowed"
    );
}

#[test]
fn previous_window_decays_linearly_across_the_window() {
    // Each observe mutates the sketch, so rebuild fresh per probe. The observe at WINDOW rotates
    // into window 2 and re-anchors the clock, so window 2's decay starts clean.
    let build = |probe_time: u64, threshold: u32| -> bool {
        let mut s = Sketch::new();
        let key = key_from_v4(0x0A00_000A);
        for _ in 0..100 {
            s.observe_over_limit(key, 0, WINDOW, u32::MAX); // window 1 -> count 100
        }
        s.observe_over_limit(key, WINDOW, WINDOW, u32::MAX); // rotate; current = 1
        s.observe_over_limit(key, probe_time, WINDOW, threshold) // current -> 2
    };

    // Half left: previous ~50 + current 2 = 52.
    let half = WINDOW + WINDOW / 2;
    assert!(build(half, 51), "at half window, estimate ~52 is over 51");
    assert!(!build(half, 52), "at half window, estimate ~52 is not over 52");

    // Quarter left: previous ~25 + current 2 = 27.
    let three_quarters = WINDOW + WINDOW * 3 / 4;
    assert!(build(three_quarters, 26), "at 3/4 window, estimate ~27 is over 26");
    assert!(!build(three_quarters, 27), "at 3/4 window, estimate ~27 is not over 27");
}

#[test]
fn distinct_keys_do_not_affect_each_other() {
    let mut s = Sketch::new();
    let threshold = 4;
    let a = key_from_v4(0x0A00_0003);
    for _ in 0..100 {
        s.observe_over_limit(a, 0, WINDOW, threshold);
    }
    // B's 4 cells don't collide with A's, so flooding A leaves B unaffected.
    let b = key_from_v4(0xC0A8_0001);
    assert!(
        !s.observe_over_limit(b, 0, WINDOW, threshold),
        "distinct key not over the limit"
    );
}

#[test]
fn point_estimate_never_underreports_a_heavy_key() {
    // The grid overcounts on collisions, never undercounts: after N SYNs the estimate (min of
    // the 4 cells) must be >= N.
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0004);
    let n = 50u32;
    // Threshold impossibly high so nothing goes over; we only read the raw cells afterwards.
    for _ in 0..n {
        s.observe_over_limit(key, 0, WINDOW, u32::MAX);
    }
    let base = (s.active_slot as usize).saturating_mul(SLOT_LEN);
    let cols = cell_indices(key);
    let mut min = u32::MAX;
    for (row, &col) in cols.iter().enumerate() {
        let idx = base
            .saturating_add(row.saturating_mul(SLOTS))
            .saturating_add(col);
        let c = u32::from(s.counters[idx]);
        if c < min {
            min = c;
        }
    }
    assert!(min >= n, "estimate {min} must be >= true count {n}");
}

#[test]
fn v6_key_is_stable_and_mixes_both_halves() {
    let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    assert_eq!(key_v6(addr, SEED), key_v6(addr, SEED), "the key is deterministic for a seed");
    // Changing a byte in the low half (bytes 8..16) must change the key.
    let mut low = addr;
    low[15] = 0x02;
    assert_ne!(key_v6(addr, SEED), key_v6(low, SEED), "low half affects the key");
    // Changing a byte in the high half (bytes 0..8) must change the key too.
    let mut high = addr;
    high[0] = 0x21;
    assert_ne!(key_v6(addr, SEED), key_v6(high, SEED), "high half affects the key");
}

#[test]
fn v6_key_goes_over_limit() {
    let mut s = Sketch::new();
    let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    let key = key_v6(addr, SEED);
    let threshold = 3;
    for i in 1..=threshold {
        assert!(!s.observe_over_limit(key, 0, WINDOW, threshold), "v6 observation {i} allowed");
    }
    assert!(
        s.observe_over_limit(key, 0, WINDOW, threshold),
        "4th v6 SYN goes over the limit"
    );
}

#[test]
fn window_zero_disables_rotation() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0005);
    let threshold = 2;
    for _ in 0..3 {
        s.observe_over_limit(key, 0, 0, threshold);
    }
    // window=0 means never rotate: even with the clock jumped to the max, the count keeps growing.
    assert!(s.observe_over_limit(key, u64::MAX, 0, threshold), "no rotation when window=0");
}

#[test]
fn threshold_zero_blocks_the_first_syn() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0006);
    // threshold 0: the first SYN's count of 1 is already over.
    assert!(
        s.observe_over_limit(key, 0, WINDOW, 0),
        "first SYN should already be over a threshold of 0"
    );
}

#[test]
fn just_under_the_window_does_not_rotate() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0007);
    let threshold = 3;
    for _ in 0..10 {
        s.observe_over_limit(key, 0, WINDOW, threshold);
    }
    assert!(
        s.observe_over_limit(key, 0, WINDOW, threshold),
        "over the limit before the window ends"
    );
    // 1ns before the window ends: same window, count not reset, still over.
    assert!(
        s.observe_over_limit(key, WINDOW - 1, WINDOW, threshold),
        "still over the limit one ns before the window ends"
    );
}

#[test]
fn a_long_quiet_gap_still_resets_the_count_on_the_next_syn() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0008);
    let threshold = 3;
    for _ in 0..10 {
        s.observe_over_limit(key, 0, WINDOW, threshold);
    }
    assert!(s.observe_over_limit(key, 0, WINDOW, threshold), "over the limit in window 1");
    // Quiet for 10 windows: 2+ elapsed, so both grids are stale and counting restarts from 0.
    let over = s.observe_over_limit(key, WINDOW.saturating_mul(10), WINDOW, threshold);
    assert!(!over, "first SYN after a long quiet gap is allowed, not still over the limit");
}

#[test]
fn counters_saturate_instead_of_wrapping_at_the_max() {
    let mut s = Sketch::new();
    let key = key_from_v4(0x0A00_0009);
    let base = (s.active_slot as usize).saturating_mul(SLOT_LEN);
    let cols = cell_indices(key);
    // Pin every cell this key touches to the u16 ceiling.
    for (row, &col) in cols.iter().enumerate() {
        let idx = base
            .saturating_add(row.saturating_mul(SLOTS))
            .saturating_add(col);
        s.counters[idx] = u16::MAX;
    }
    // One more observation must saturate, not wrap to 0.
    let over = s.observe_over_limit(key, 0, WINDOW, u32::from(u16::MAX) - 1);
    assert!(over, "count must saturate at u16::MAX, not wrap around and look allowed");
}

#[test]
fn max_threshold_is_the_largest_one_a_single_window_can_cross() {
    // Saturating u16 counters cap one window's count at 65535, so MAX_THRESHOLD is the last
    // threshold a window can push past on its own. Above it a window never fires, however many
    // SYNs arrive, which is why configs must reject it (see the HUGINN_EBPF_RATE_LIMIT_BURST
    // bound in huginn-ebpf-agent).
    let key = key_from_v4(0x0A00_000A);
    let saturate = u32::from(u16::MAX).saturating_add(1);

    let mut at_max = Sketch::new();
    let fired = (0..saturate).any(|_| at_max.observe_over_limit(key, 1, WINDOW, MAX_THRESHOLD));
    assert!(fired, "MAX_THRESHOLD must still be reachable");

    let mut over_max = Sketch::new();
    let fired = (0..saturate)
        .any(|_| over_max.observe_over_limit(key, 1, WINDOW, MAX_THRESHOLD.saturating_add(1)));
    assert!(!fired, "a single window cannot cross a threshold above MAX_THRESHOLD");
}

// --- keyed hashing ---------------------------------------------------------------------------

#[test]
fn the_seed_decides_where_a_v4_source_lands() {
    let ip = 0x0A00_0B0Cu32;
    let a = cell_indices(key_v4(ip, SEED));
    let b = cell_indices(key_v4(ip, SEED ^ 1));
    assert_ne!(a, b, "one seed bit must move the cells; otherwise the grid layout is public");
    assert_eq!(
        cell_indices(key_v4(ip, SEED)),
        a,
        "the same seed must keep placing an IP in the same cells, or counting breaks"
    );
}

#[test]
fn the_seed_decides_where_a_v6_source_lands() {
    let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07];
    assert_ne!(
        cell_indices(key_v6(addr, SEED)),
        cell_indices(key_v6(addr, SEED ^ 1)),
        "one seed bit must move the cells for v6 too"
    );
}

#[test]
fn a_v6_attacker_in_one_prefix_cannot_land_on_a_victims_key() {
    // The old `hi ^ lo` key gave an exact collision for free: pick
    // `lo = victim_hi ^ victim_lo ^ attacker_hi` from any /64. Chaining through the mixer closes
    // that off.
    let victim = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x42];
    let victim_hi = u64::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x01]);
    let victim_lo = u64::from_ne_bytes([0, 0, 0, 0, 0, 0, 0, 0x42]);

    // Attacker's /64, plus the low half the old XOR fold would collide on.
    let attacker_hi_bytes = [0x2a, 0x00, 0x14, 0x50, 0, 0, 0, 0x99];
    let attacker_hi = u64::from_ne_bytes(attacker_hi_bytes);
    let forged_lo = (victim_hi ^ victim_lo ^ attacker_hi).to_ne_bytes();

    let mut attacker = [0u8; 16];
    attacker[..8].copy_from_slice(&attacker_hi_bytes);
    attacker[8..].copy_from_slice(&forged_lo);

    assert_eq!(
        attacker_hi ^ u64::from_ne_bytes(forged_lo),
        victim_hi ^ victim_lo,
        "the address really is an XOR-fold collision, so this test would fail against that fold"
    );
    assert_ne!(
        key_v6(attacker, SEED),
        key_v6(victim, SEED),
        "an XOR-fold collision must no longer be a key collision"
    );
}

#[test]
fn no_two_addresses_in_one_prefix_share_a_key() {
    // Same /64, varying low halves: every address gets its own key. Cell collisions still
    // happen (inherent to the sketch) but can't be aimed.
    let mut seen = std::collections::HashSet::new();
    for i in 0..20_000u64 {
        let mut addr = [0u8; 16];
        addr[..8].copy_from_slice(&[0x2a, 0x00, 0x14, 0x50, 0, 0, 0, 0x99]);
        addr[8..].copy_from_slice(&i.to_ne_bytes());
        assert!(seen.insert(key_v6(addr, SEED)), "two addresses in one /64 share a key at i={i}");
    }
}

#[test]
fn no_two_v4_addresses_share_a_key() {
    let mut seen = std::collections::HashSet::new();
    for i in 0..20_000u32 {
        let ip = 0x0100_0000u32.wrapping_add(i.wrapping_mul(7919));
        assert!(seen.insert(key_v4(ip, SEED)), "two IPv4 addresses share a key at i={i}");
    }
}

#[test]
fn suppressing_a_victim_takes_a_flood_the_attacker_cannot_target() {
    // End to end: flood with ~4x threshold spoofed SYNs (a targeted attack's budget) and a
    // specific victim must still be under its limit.
    let mut s = Sketch::new();
    let threshold = 50u32;
    let victim = 0x0A00_00FFu32;
    for i in 0..threshold.saturating_mul(4) {
        let spoofed = 0xC000_0000u32.wrapping_add(i);
        s.observe_over_limit(key_v4(spoofed, SEED), 0, WINDOW, threshold);
    }
    assert!(
        !s.observe_over_limit(key_v4(victim, SEED), 0, WINDOW, threshold),
        "a victim must not be pushed over the limit by a flood that could not target it"
    );
}
