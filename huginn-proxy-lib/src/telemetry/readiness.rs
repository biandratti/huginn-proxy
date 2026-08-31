//! Readiness state shared between the proxy and the observability server's `/ready` endpoint.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Result of an optional extra readiness check (e.g. capture health).
///
/// The proxy library does not know what the check is; the binary injects a
/// [`ReadinessGate`] when a feature needs to AND another condition into `/ready`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GateState {
    Ready = 0,
    Absent = 1,
    Draining = 2,
    Detached = 3,
}

impl GateState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ready,
            2 => Self::Draining,
            3 => Self::Detached,
            _ => Self::Absent,
        }
    }

    pub fn reason(self) -> Option<NotReadyReason> {
        match self {
            Self::Ready => None,
            Self::Absent => Some(NotReadyReason::CaptureAbsent),
            Self::Draining => Some(NotReadyReason::CaptureDraining),
            Self::Detached => Some(NotReadyReason::CaptureDetached),
        }
    }
}

/// Lock-free extra check consulted after the proxy's own starting/draining flags.
pub type ReadinessGate = Arc<dyn Fn() -> GateState + Send + Sync>;

/// Why `/ready` is 503. Serialized as the JSON `reason` snake_case string at the HTTP edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotReadyReason {
    ProxyStarting,
    ProxyDraining,
    CaptureAbsent,
    CaptureDraining,
    CaptureDetached,
}

impl NotReadyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyStarting => "proxy_starting",
            Self::ProxyDraining => "proxy_draining",
            Self::CaptureAbsent => "capture_absent",
            Self::CaptureDraining => "capture_draining",
            Self::CaptureDetached => "capture_detached",
        }
    }

    pub const fn text_token(self) -> &'static str {
        match self {
            Self::ProxyStarting => "STARTING",
            Self::ProxyDraining => "DRAINING",
            Self::CaptureAbsent | Self::CaptureDraining | Self::CaptureDetached => "NOCAPTURE",
        }
    }
}

struct Inner {
    ready: AtomicBool,
    draining: AtomicBool,
    gate: OnceLock<ReadinessGate>,
}

#[derive(Clone)]
pub struct Readiness(Arc<Inner>);

impl Default for Readiness {
    fn default() -> Self {
        Self(Arc::new(Inner {
            ready: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            gate: OnceLock::new(),
        }))
    }
}

impl Readiness {
    /// Create a new handle in the not-ready state (`proxy_starting`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Install an extra AND-ed check. Call once; later calls are ignored.
    pub fn set_gate(&self, gate: ReadinessGate) {
        let _ = self.0.gate.set(gate);
    }

    /// Mark the proxy as ready to accept traffic (`/ready` -> 200 if the gate agrees).
    pub fn mark_ready(&self) {
        self.0.draining.store(false, Ordering::Release);
        self.0.ready.store(true, Ordering::Release);
    }

    /// Mark the proxy as not ready (`/ready` -> 503), e.g. during graceful shutdown.
    pub fn mark_not_ready(&self) {
        self.0.ready.store(false, Ordering::Release);
    }

    /// Fail `/ready` with `proxy_draining` while listeners still accept.
    pub fn mark_draining(&self) {
        self.0.draining.store(true, Ordering::Release);
        self.0.ready.store(false, Ordering::Release);
    }

    /// Whether `/ready` would return 200. Same source of truth as the HTTP probe
    /// (`not_ready_reason`).
    pub fn is_ready(&self) -> bool {
        self.not_ready_reason().is_none()
    }

    /// `None` when ready; otherwise why `/ready` is 503.
    ///
    /// Priority: `proxy_draining`, then `proxy_starting`, then the optional gate.
    pub fn not_ready_reason(&self) -> Option<NotReadyReason> {
        if self.0.draining.load(Ordering::Acquire) {
            return Some(NotReadyReason::ProxyDraining);
        }
        if !self.0.ready.load(Ordering::Acquire) {
            return Some(NotReadyReason::ProxyStarting);
        }
        self.0.gate.get().and_then(|gate| gate().reason())
    }
}
