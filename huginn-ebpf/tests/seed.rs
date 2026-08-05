use std::collections::HashSet;

use huginn_ebpf::probe::random_seed;

#[test]
fn draws_many_distinct_seeds() {
    const DRAWS: usize = 64;
    let mut seen = HashSet::with_capacity(DRAWS);
    for i in 0..DRAWS {
        let seed = random_seed().unwrap_or_else(|e| panic!("could not draw seed {i}: {e}"));
        assert!(
            seen.insert(seed),
            "seed collision at draw {i}: {seed:#x} already seen (seed must be fresh per load)"
        );
    }
    assert_eq!(seen.len(), DRAWS);
}
