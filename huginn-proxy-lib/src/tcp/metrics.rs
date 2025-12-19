#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub struct ConnectionCount {
    current: AtomicUsize,
    total: AtomicUsize,
    errors: AtomicUsize,
}

impl ConnectionCount {
    pub fn increment(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.current
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .ok();
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    // TODO: remove this once we have a proper metrics system
    #[allow(dead_code)]
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    // TODO: remove this once we have a proper metrics system
    #[allow(dead_code)]
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    // TODO: remove this once we have a proper metrics system
    #[allow(dead_code)]
    pub fn errors(&self) -> usize {
        self.errors.load(Ordering::Relaxed)
    }
}
