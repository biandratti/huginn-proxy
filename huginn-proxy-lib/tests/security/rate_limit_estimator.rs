use huginn_proxy_lib::security::rate_limit::Rate;

#[test]
fn test_estimator_basic_operations() {
    use std::time::Duration;
    let rate = Rate::new(Duration::from_secs(1));

    // Test increment operations
    let count1 = rate.observe(&"test-key", 1);
    assert_eq!(count1, 1);

    let count2 = rate.observe(&"test-key", 2);
    assert_eq!(count2, 3);

    // Different key should be independent
    let count3 = rate.observe(&"other-key", 5);
    assert_eq!(count3, 5);

    // Original key should still be 3
    let count4 = rate.observe(&"test-key", 0);
    assert_eq!(count4, 3);
}

#[test]
fn test_estimator_multiple_keys_independent() {
    use std::time::Duration;
    let rate = Rate::new(Duration::from_secs(1));

    // Test many independent keys
    for i in 0..100 {
        let key = format!("key-{}", i);
        rate.observe(&key, 1);
    }

    // Verify each key has count of 1
    for i in 0..100 {
        let key = format!("key-{}", i);
        let count = rate.observe(&key, 0);
        assert_eq!(count, 1);
    }
}

#[test]
fn test_estimator_get_operation() {
    use std::time::Duration;
    let rate = Rate::new(Duration::from_secs(1));

    rate.observe(&"a", 1);
    rate.observe(&"a", 2);
    rate.observe(&"b", 1);
    rate.observe(&"b", 2);

    assert_eq!(rate.observe(&"a", 0), 3);
    assert_eq!(rate.observe(&"b", 0), 3);
}

#[test]
fn test_estimator_reset_on_window_change() {
    use std::thread::sleep;
    use std::time::Duration;

    let rate = Rate::new(Duration::from_millis(100));
    let key = "test";

    rate.observe(&key, 5);
    assert_eq!(rate.observe(&key, 0), 5);

    // Wait for window to reset
    sleep(Duration::from_millis(150));

    // Should start fresh (reset)
    assert_eq!(rate.observe(&key, 3), 3);
}
