use huginn_proxy_lib::security::rate_limit::{RateLimitResult, RateLimiter};
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_basic_rate_limiting() {
    let limiter = RateLimiter::new(10, 20, Duration::from_secs(1)); // 10 rps, burst 20
    let key = "test-key";

    // Should allow first 20 requests (burst)
    for i in 0..20 {
        let result = limiter.check(&key);
        assert!(result.is_allowed(), "Request {} should be allowed, got {:?}", i, result);
    }

    // 21st request should be limited
    let result = limiter.check(&key);
    assert!(result.is_limited(), "Request 21 should be limited, got {:?}", result);
    assert_eq!(result.remaining(), 0);
    assert_eq!(result.limit(), 20);

    // After 1 second, should allow more requests
    sleep(Duration::from_secs(1));
    let result = limiter.check(&key);
    assert!(result.is_allowed(), "After reset, request should be allowed, got {:?}", result);
}

#[test]
fn test_multiple_keys() {
    let limiter = RateLimiter::new(5, 10, Duration::from_secs(1));

    // Different keys should have independent limits
    for _ in 0..10 {
        assert!(limiter.check(&"key1").is_allowed());
    }

    for _ in 0..10 {
        assert!(limiter.check(&"key2").is_allowed());
    }

    // Both should be limited now
    assert!(limiter.check(&"key1").is_limited());
    assert!(limiter.check(&"key2").is_limited());
}

#[test]
fn test_check_only() {
    let limiter = RateLimiter::new(10, 5, Duration::from_secs(1));
    let key = "test";

    // check_only should not increment counter
    for _ in 0..10 {
        let result = limiter.check_only(&key);
        assert!(result.is_allowed());
    }

    // Now actually check (which increments)
    for i in 0..5 {
        let result = limiter.check(&key);
        assert!(result.is_allowed(), "Request {} should be allowed", i);
    }

    // Next should be limited
    assert!(limiter.check(&key).is_limited());
}

#[test]
fn test_remaining_count() {
    let limiter = RateLimiter::new(10, 10, Duration::from_secs(1));
    let key = "test";

    // Check remaining count decreases
    for i in 0..10 {
        let result = limiter.check(&key);
        assert!(result.is_allowed());
        assert_eq!(result.remaining(), 10 - i - 1);
    }

    // When limited, remaining should be 0
    let result = limiter.check(&key);
    assert!(result.is_limited());
    assert_eq!(result.remaining(), 0);
}

#[test]
fn test_result_methods() {
    let limiter = RateLimiter::new(10, 5, Duration::from_secs(1));

    let allowed = limiter.check(&"key1");
    assert!(allowed.is_allowed());
    assert!(!allowed.is_limited());
    assert_eq!(allowed.limit(), 5);
    assert!(allowed.remaining() > 0);
    assert!(allowed.reset_after().is_none());

    // Exhaust the limit
    for _ in 0..5 {
        limiter.check(&"key2");
    }

    let limited = limiter.check(&"key2");
    assert!(!limited.is_allowed());
    assert!(limited.is_limited());
    assert_eq!(limited.limit(), 5);
    assert_eq!(limited.remaining(), 0);
    assert!(limited.reset_after().is_some());
    if let Some(reset_after) = limited.reset_after() {
        assert_eq!(reset_after, Duration::from_secs(1));
    }
}

#[test]
fn test_concurrent_limiting() {
    use std::sync::Arc;
    use std::thread;

    let limiter = Arc::new(RateLimiter::new(100, 50, Duration::from_secs(1)));
    let mut handles = vec![];

    // Spawn multiple threads trying to use the same key
    for _ in 0..5 {
        let limiter_clone = Arc::clone(&limiter);
        let handle = thread::spawn(move || {
            let mut allowed = 0;
            let mut limited = 0;

            for _ in 0..20 {
                match limiter_clone.check(&"shared-key") {
                    RateLimitResult::Allowed { .. } => allowed += 1,
                    RateLimitResult::Limited { .. } => limited += 1,
                }
            }

            (allowed, limited)
        });
        handles.push(handle);
    }

    let mut total_allowed = 0;
    let mut total_limited = 0;

    for handle in handles {
        let (allowed, limited) = match handle.join() {
            Ok(result) => result,
            Err(_) => panic!("Thread should complete successfully"),
        };
        total_allowed += allowed;
        total_limited += limited;
    }

    // Total requests = 5 threads × 20 requests = 100
    assert_eq!(total_allowed + total_limited, 100);
    // Should allow up to burst limit (50)
    assert!(total_allowed <= 50);
    // Rest should be limited
    assert!(total_limited >= 50);
}
