use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct RoundRobin {
    index: Arc<AtomicUsize>,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self { index: Arc::new(AtomicUsize::new(0)) }
    }

    /// Get the next index in round-robin fashion
    pub fn next(&self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        self.index
            .fetch_add(1, Ordering::Relaxed)
            .checked_rem(len)
            .unwrap_or(0)
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}
