use std::time::Duration;

use super::check_tcp::check_tcp;
use super::counter::ConsecutiveCounter;

type TestError = Box<dyn std::error::Error + Send + Sync>;

// ── ConsecutiveCounter ────────────────────────────────────────────────────────

#[test]
fn becomes_unhealthy_after_threshold() {
    let mut c = ConsecutiveCounter::new(3, 2);
    assert!(c.record(false).is_none());
    assert!(c.record(false).is_none());
    assert_eq!(c.record(false), Some(false));
    assert!(!c.is_healthy());
}

#[test]
fn recovers_after_healthy_threshold() {
    let mut c = ConsecutiveCounter::new(3, 2);
    c.record(false);
    c.record(false);
    c.record(false);
    assert!(!c.is_healthy());
    assert!(c.record(true).is_none());
    assert_eq!(c.record(true), Some(true));
    assert!(c.is_healthy());
}

#[test]
fn intermittent_failures_reset_counter() {
    let mut c = ConsecutiveCounter::new(3, 2);
    c.record(false);
    c.record(false);
    c.record(true);
    c.record(false);
    c.record(false);
    assert!(c.record(true).is_none());
    assert!(c.is_healthy());
}

#[test]
fn intermittent_successes_reset_recovery() {
    let mut c = ConsecutiveCounter::new(1, 3);
    assert_eq!(c.record(false), Some(false));
    c.record(true);
    c.record(true);
    c.record(false);
    c.record(true);
    assert!(c.record(true).is_none());
    assert!(!c.is_healthy());
    assert_eq!(c.record(true), Some(true));
    assert!(c.is_healthy());
}

#[test]
fn no_spurious_transitions_when_already_healthy() {
    let mut c = ConsecutiveCounter::new(3, 2);
    assert!(c.record(true).is_none());
    assert!(c.record(true).is_none());
    assert!(c.record(true).is_none());
    assert!(c.is_healthy());
}

#[test]
fn no_spurious_transitions_when_already_unhealthy() {
    let mut c = ConsecutiveCounter::new(1, 2);
    assert_eq!(c.record(false), Some(false));
    assert!(c.record(false).is_none());
    assert!(c.record(false).is_none());
    assert!(!c.is_healthy());
}

#[test]
fn threshold_one_transitions_immediately() {
    let mut c = ConsecutiveCounter::new(1, 1);
    assert_eq!(c.record(false), Some(false));
    assert_eq!(c.record(true), Some(true));
    assert_eq!(c.record(false), Some(false));
}

#[test]
fn threshold_zero_is_clamped_to_one() {
    let mut c = ConsecutiveCounter::new(0, 0);
    assert_eq!(c.record(false), Some(false));
    assert_eq!(c.record(true), Some(true));
}

#[test]
fn streak_does_not_overflow() {
    let mut c = ConsecutiveCounter::new(u32::MAX, u32::MAX);
    for _ in 0..1_000 {
        assert!(c.record(true).is_none());
    }
    assert!(c.is_healthy());
}

// ── check_tcp ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tcp_returns_true_for_listening_port() -> Result<(), TestError> {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    assert!(check_tcp(&addr, Duration::from_secs(2)).await);
    Ok(())
}

#[tokio::test]
async fn tcp_returns_false_for_unreachable_port() {
    // Port 1 is reserved and almost certainly not listening.
    assert!(!check_tcp("127.0.0.1:1", Duration::from_millis(500)).await);
}

#[tokio::test]
async fn tcp_returns_false_for_invalid_address() {
    assert!(!check_tcp("not a real address", Duration::from_millis(500)).await);
}

#[tokio::test]
async fn tcp_returns_false_when_dns_fails() {
    // RFC 6761 reserves .invalid for guaranteed-NXDOMAIN names.
    assert!(!check_tcp("nonexistent.invalid:80", Duration::from_secs(1)).await);
}

#[tokio::test]
async fn tcp_ipv6_listener_is_reachable() -> Result<(), TestError> {
    use tokio::net::TcpListener;
    let listener = match TcpListener::bind("[::1]:0").await {
        Ok(l) => l,
        // Skip on environments without IPv6 loopback (CI containers, etc.).
        Err(_) => return Ok(()),
    };
    let addr = listener.local_addr()?.to_string();
    assert!(check_tcp(&addr, Duration::from_secs(2)).await);
    Ok(())
}

#[tokio::test]
async fn tcp_timeout_returns_false_quickly() {
    // 10.255.255.1 is a non-routable address that will hang on connect.
    // We expect the timeout to fire well before the OS connect timeout (~75s).
    let start = std::time::Instant::now();
    let res = check_tcp("10.255.255.1:1", Duration::from_millis(200)).await;
    let elapsed = start.elapsed();
    assert!(!res);
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout did not fire quickly: elapsed = {elapsed:?}"
    );
}
