use huginn_proxy_lib::security::rate_limit::{RateLimitResult, RateLimiter};
use std::time::Duration;

#[test]
fn test_rate_limiter_creation() {
    let limiter = RateLimiter::new(100, 200, Duration::from_secs(1));
    assert_eq!(limiter.max_requests(), 200);
    assert_eq!(limiter.window(), Duration::from_secs(1));
}

#[test]
fn test_basic_flow() {
    let limiter = RateLimiter::new(10, 5, Duration::from_secs(1));

    // First 5 requests should be allowed
    for _ in 0..5 {
        assert!(limiter.check(&"test").is_allowed());
    }

    // 6th request should be limited
    assert!(limiter.check(&"test").is_limited());
}

#[test]
fn test_rate_limiter_accuracy() {
    let limiter = RateLimiter::new(100, 200, Duration::from_secs(1));
    let key = "client-ip-1.2.3.4";

    // Simulate 200 requests rapidly
    let mut allowed = 0;
    let mut limited = 0;

    for _ in 0..250 {
        match limiter.check(&key) {
            RateLimitResult::Allowed { .. } => allowed += 1,
            RateLimitResult::Limited { .. } => limited += 1,
        }
    }

    // Should allow burst amount
    assert_eq!(allowed, 200, "Should allow up to burst limit");
    assert_eq!(limited, 50, "Should limit excess requests");
}

#[test]
fn test_multiple_keys_independent() {
    let limiter = RateLimiter::new(10, 10, Duration::from_secs(1));

    // Exhaust limit for key1
    for _ in 0..10 {
        assert!(limiter.check(&"key1").is_allowed());
    }
    assert!(limiter.check(&"key1").is_limited());

    // key2 should still be allowed
    for _ in 0..10 {
        assert!(limiter.check(&"key2").is_allowed());
    }
    assert!(limiter.check(&"key2").is_limited());
}

#[test]
fn test_result_api() {
    let limiter = RateLimiter::new(10, 5, Duration::from_secs(1));

    let result = limiter.check(&"test");
    assert!(result.is_allowed());
    assert!(!result.is_limited());
    assert_eq!(result.limit(), 5);
    assert!(result.remaining() > 0);
    assert!(result.reset_after().is_none());

    // Exhaust limit
    for _ in 0..5 {
        limiter.check(&"test2");
    }

    let result = limiter.check(&"test2");
    assert!(!result.is_allowed());
    assert!(result.is_limited());
    assert_eq!(result.limit(), 5);
    assert_eq!(result.remaining(), 0);
    assert!(result.reset_after().is_some());
    if let Some(reset_after) = result.reset_after() {
        assert_eq!(reset_after, Duration::from_secs(1));
    }
}

#[test]
fn test_check_only_does_not_increment() {
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
fn test_remaining_count_decreases() {
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
fn test_concurrent_access() {
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
