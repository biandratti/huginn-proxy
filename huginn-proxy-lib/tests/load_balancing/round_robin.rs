use huginn_proxy_lib::load_balancing::RoundRobin;

#[test]
fn test_round_robin_basic() {
    let rr = RoundRobin::new();
    assert_eq!(rr.next(3), 0);
    assert_eq!(rr.next(3), 1);
    assert_eq!(rr.next(3), 2);
    assert_eq!(rr.next(3), 0); // Wraps around
}

#[test]
fn test_round_robin_single_backend() {
    let rr = RoundRobin::new();
    assert_eq!(rr.next(1), 0);
    assert_eq!(rr.next(1), 0);
    assert_eq!(rr.next(1), 0);
}

#[test]
fn test_round_robin_empty() {
    let rr = RoundRobin::new();
    // Should return 0 for empty list (safe default)
    assert_eq!(rr.next(0), 0);
    assert_eq!(rr.next(0), 0);
}

#[test]
fn test_round_robin_wraparound() {
    let rr = RoundRobin::new();
    let len = 5;

    // First cycle
    for i in 0..len {
        assert_eq!(rr.next(len), i);
    }

    // Second cycle (should wrap around)
    for i in 0..len {
        assert_eq!(rr.next(len), i);
    }
}

#[test]
fn test_round_robin_concurrent() {
    use std::sync::Arc;
    use std::thread;

    let rr = Arc::new(RoundRobin::new());
    let len = 10;
    let num_threads = 4;
    let iterations_per_thread = 100;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let rr = Arc::clone(&rr);
            thread::spawn(move || {
                let mut results = Vec::new();
                for _ in 0..iterations_per_thread {
                    results.push(rr.next(len));
                }
                results
            })
        })
        .collect();

    let all_results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| panic!("All threads should complete successfully"))
        .into_iter()
        .flatten()
        .collect();

    // Verify all results are valid indices
    for &idx in &all_results {
        assert!(idx < len, "Index {idx} out of bounds for length {len}");
    }

    // Verify we got all indices (distribution test)
    let mut counts = vec![0; len];
    for &idx in &all_results {
        counts[idx] += 1;
    }

    // Each index should appear roughly the same number of times
    // (allowing for some variance due to race conditions)
    let expected_count = (num_threads * iterations_per_thread) / len;
    for (i, &count) in counts.iter().enumerate() {
        assert!(count > 0, "Index {i} was never selected");
        // Allow 20% variance
        let min_expected = (expected_count as f64 * 0.8) as usize;
        let max_expected = (expected_count as f64 * 1.2) as usize;
        assert!(
            count >= min_expected && count <= max_expected,
            "Index {i} count {count} outside expected range [{min_expected}, {max_expected}]"
        );
    }
}

#[test]
fn test_round_robin_default() {
    let rr = RoundRobin::default();
    assert_eq!(rr.next(3), 0);
    assert_eq!(rr.next(3), 1);
}

#[test]
fn test_round_robin_large_number() {
    let rr = RoundRobin::new();
    let len = 1000;

    // Test wraparound with large numbers
    for _ in 0..len * 2 {
        let idx = rr.next(len);
        assert!(idx < len);
    }
}
