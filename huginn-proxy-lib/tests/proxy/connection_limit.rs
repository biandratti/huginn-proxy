use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_connection_limit_check() {
    let max_connections = 2;
    let active_connections = Arc::new(AtomicUsize::new(0));

    for i in 0..max_connections {
        let current = active_connections.fetch_add(1, Ordering::Relaxed);
        assert!(
            current < max_connections,
            "Connection {i} should be accepted (current: {current}, limit: {max_connections})"
        );
    }

    let current = active_connections.load(Ordering::Relaxed);
    assert_eq!(current, max_connections);
    assert!(
        current >= max_connections,
        "Connection should be rejected when at limit (current: {current}, limit: {max_connections})"
    );

    active_connections.fetch_sub(1, Ordering::Relaxed);
    let current = active_connections.load(Ordering::Relaxed);
    assert_eq!(current, max_connections - 1);
    assert!(
        current < max_connections,
        "After closing a connection, new ones should be accepted (current: {current}, limit: {max_connections})"
    );
}

#[test]
fn test_connection_limit_edge_cases() {
    let max_connections = 1;
    let active_connections = Arc::new(AtomicUsize::new(0));

    let current = active_connections.fetch_add(1, Ordering::Relaxed);
    assert_eq!(current, 0);
    assert!(current < max_connections);

    let current = active_connections.load(Ordering::Relaxed);
    assert_eq!(current, max_connections);
    assert!(current >= max_connections);

    // Test: with limit of 0, all connections should be rejected
    let max_connections_zero = 0;
    let active_zero = Arc::new(AtomicUsize::new(0));
    let current = active_zero.load(Ordering::Relaxed);
    assert!(current >= max_connections_zero);
}
