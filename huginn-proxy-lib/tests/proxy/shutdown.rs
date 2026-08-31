use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use huginn_proxy_lib::proxy::shutdown::wait_for_drain;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn wait_for_drain_returns_immediately_when_idle() {
    let (_tx, rx) = watch::channel(());
    let active = Arc::new(AtomicUsize::new(0));
    wait_for_drain(rx, active, 30).await;
}

#[tokio::test]
async fn wait_for_drain_ignores_stale_notification() {
    let (tx, rx) = watch::channel(());
    let active = Arc::new(AtomicUsize::new(2));
    let _ = tx.send(());

    let waiter = tokio::spawn({
        let active = Arc::clone(&active);
        async move { wait_for_drain(rx, active, 5).await }
    });

    sleep(Duration::from_millis(50)).await;
    assert!(!waiter.is_finished(), "stale notification must not complete drain");

    active.store(1, Ordering::Relaxed);
    let _ = tx.send(());
    sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished(), "must wait until the last connection");

    active.store(0, Ordering::Relaxed);
    let _ = tx.send(());
    assert!(waiter.await.is_ok());
}

#[tokio::test]
async fn wait_for_drain_times_out_with_connections_still_active() {
    let (_tx, rx) = watch::channel(());
    let active = Arc::new(AtomicUsize::new(3));
    wait_for_drain(rx, active, 0).await;
}
