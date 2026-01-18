use huginn_proxy_lib::security::rate_limit::Rate;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_interval_getter() {
    let rate = Rate::new(Duration::from_secs(1));
    assert_eq!(rate.interval(), Duration::from_secs(1));

    let rate2 = Rate::new(Duration::from_millis(500));
    assert_eq!(rate2.interval(), Duration::from_millis(500));
}

#[test]
fn test_observe_rate() {
    let r = Rate::new(Duration::from_secs(1));
    let key = 1;

    // second: 0
    let observed = r.observe(&key, 3);
    assert_eq!(observed, 3);
    let observed = r.observe(&key, 2);
    assert_eq!(observed, 5);
    assert_eq!(r.rate(&key), 0f64); // no estimation yet because the interval has not passed

    // second: 1
    sleep(Duration::from_secs(1));
    let observed = r.observe(&key, 4);
    assert_eq!(observed, 4);
    assert_eq!(r.rate(&key), 5f64); // 5 rps

    // second: 2
    sleep(Duration::from_secs(1));
    assert_eq!(r.rate(&key), 4f64);

    // second: 3
    sleep(Duration::from_secs(1));
    assert_eq!(r.rate(&key), 0f64); // no event observed in the past 2 seconds
}

#[test]
fn test_multiple_keys() {
    let r = Rate::new(Duration::from_secs(1));

    // Different keys should be tracked independently
    r.observe(&"key1", 10);
    r.observe(&"key2", 20);
    r.observe(&"key3", 30);

    assert_eq!(r.observe(&"key1", 0), 10);
    assert_eq!(r.observe(&"key2", 0), 20);
    assert_eq!(r.observe(&"key3", 0), 30);
}

#[test]
fn test_window_reset() {
    let r = Rate::new(Duration::from_millis(100));
    let key = "test";

    r.observe(&key, 5);
    assert_eq!(r.observe(&key, 0), 5);

    // Wait for window to reset
    sleep(Duration::from_millis(150));

    // Should start fresh
    assert_eq!(r.observe(&key, 3), 3);
}

#[test]
fn test_concurrent_access() {
    use std::sync::Arc;
    use std::thread;

    let rate = Arc::new(Rate::new(Duration::from_secs(1)));
    let mut handles = vec![];

    // Spawn multiple threads
    for i in 0..10 {
        let rate_clone = Arc::clone(&rate);
        let handle = thread::spawn(move || {
            let key = format!("thread-{}", i);
            for _ in 0..100 {
                rate_clone.observe(&key, 1);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        if handle.join().is_err() {
            panic!("Thread should complete successfully");
        }
    }

    // Each thread should have recorded 100 events
    for i in 0..10 {
        let key = format!("thread-{}", i);
        let count = rate.observe(&key, 0);
        assert_eq!(count, 100);
    }
}
