//! Readiness checks: BPF pins, in-process attach, and drain phase.

use huginn_ebpf::pin;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub use crate::telemetry::status::NotReadyReason;

/// The pins `/ready` gates on. Deliberately a subset of `pin::ALL_NAMES`: telemetry-only maps are
/// pinned by the loader but do not hold readiness back. `capture_state` is not required so a
/// legacy agent image without that map does not fail its own `/ready`.
pub const REQUIRED_PINS: &[&str] = &[
    pin::SYN_MAP_V4_NAME,
    pin::SYN_MAP_V6_NAME,
    pin::COUNTER_NAME,
    pin::SYN_INSERT_FAILURES_V4_NAME,
    pin::SYN_INSERT_FAILURES_V6_NAME,
    pin::SYN_CAPTURED_V4_NAME,
    pin::SYN_CAPTURED_V6_NAME,
    pin::SYN_MALFORMED_V4_NAME,
    pin::SYN_MALFORMED_V6_NAME,
];

pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    REQUIRED_PINS.iter().all(|name| base.join(name).exists())
}

/// Process-local capture health used by `/ready` and `agent_up`.
pub struct AgentHealth {
    pin_path: String,
    link_pin_path: String,
    attached: AtomicBool,
    draining: AtomicBool,
    expect_link_pin: AtomicBool,
}

impl AgentHealth {
    pub fn new(pin_path: String, link_pin_path: String) -> Arc<Self> {
        Arc::new(Self {
            pin_path,
            link_pin_path,
            attached: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            expect_link_pin: AtomicBool::new(false),
        })
    }

    pub fn pin_path(&self) -> &str {
        &self.pin_path
    }

    pub fn mark_attached(&self, link_pinned: bool) {
        self.expect_link_pin.store(link_pinned, Ordering::Release);
        self.attached.store(true, Ordering::Release);
        self.draining.store(false, Ordering::Release);
    }

    pub fn mark_draining(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.not_ready_reason().is_none()
    }

    pub fn not_ready_reason(&self) -> Option<NotReadyReason> {
        if self.draining.load(Ordering::Acquire) {
            return Some(NotReadyReason::CaptureDraining);
        }
        if !self.attached.load(Ordering::Acquire) {
            return Some(NotReadyReason::CaptureDetached);
        }
        if !pins_exist(&self.pin_path) {
            return Some(NotReadyReason::PinsNotReady);
        }
        if self.expect_link_pin.load(Ordering::Acquire) && !Path::new(&self.link_pin_path).exists()
        {
            return Some(NotReadyReason::CaptureDetached);
        }
        None
    }
}
