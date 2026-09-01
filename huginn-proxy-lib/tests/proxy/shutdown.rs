use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use huginn_proxy_lib::proxy::shutdown::{
    begin_shutdown, shutdown_channel, wait_for_drain, ShutdownPhase,
};
use huginn_proxy_lib::{NotReadyReason, Readiness};
use tokio::signal::unix::{signal, SignalKind};
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

/// Phase 1 must fail `/ready` while listeners keep accepting, so the load balancer has a
/// window to drain the node before the listen socket closes.
#[tokio::test]
async fn drain_phase_fails_ready_without_stopping_accept_loops() {
    let (Ok(mut sigterm), Ok(mut sigint)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()))
    else {
        panic!("failed to register signal handlers");
    };

    let readiness = Readiness::new();
    readiness.mark_ready();
    let (shutdown_tx, shutdown_rx) = shutdown_channel();

    let drain = tokio::spawn({
        let readiness = readiness.clone();
        async move {
            begin_shutdown(
                "SIGTERM",
                &readiness,
                &shutdown_tx,
                &mut sigterm,
                &mut sigint,
                Duration::from_millis(500),
            )
            .await;
        }
    });

    sleep(Duration::from_millis(50)).await;

    assert!(!drain.is_finished(), "still inside the drain delay");
    assert_eq!(readiness.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
    assert_eq!(*shutdown_rx.borrow(), ShutdownPhase::Draining);
    assert!(
        !shutdown_rx.borrow().is_stopping(),
        "accept loops break on Stopping only, so phase 1 keeps accepting"
    );

    assert!(drain.await.is_ok());
}

/// Default config (`drain_delay_secs = 0`) must behave as before the two-phase change:
/// fail readiness and hand over to phase 2 without sleeping.
#[tokio::test]
async fn zero_drain_delay_hands_over_without_sleeping() {
    let (Ok(mut sigterm), Ok(mut sigint)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()))
    else {
        panic!("failed to register signal handlers");
    };

    let readiness = Readiness::new();
    readiness.mark_ready();
    let (shutdown_tx, shutdown_rx) = shutdown_channel();

    let handover = tokio::time::timeout(
        Duration::from_secs(1),
        begin_shutdown(
            "SIGTERM",
            &readiness,
            &shutdown_tx,
            &mut sigterm,
            &mut sigint,
            Duration::ZERO,
        ),
    )
    .await;

    assert!(handover.is_ok(), "phase 1 must hand over without sleeping");
    assert_eq!(readiness.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
    assert_eq!(*shutdown_rx.borrow(), ShutdownPhase::Draining);
}
