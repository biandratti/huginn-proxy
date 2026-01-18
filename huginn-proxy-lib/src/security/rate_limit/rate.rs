// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The rate module defines the [Rate] type that helps estimate the occurrence of events over a
//! period of time.
//!
//! This is adapted from Pingora's implementation for use in Huginn Proxy.

use crate::security::rate_limit::estimator::Estimator;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing;

/// A stable rate estimator that reports the rate of events per period of `interval` time.
///
/// It counts events for periods of `interval` and returns the average rate of the latest completed
/// period while counting events for the current (partial) period.
///
/// # Algorithm
///
/// Uses a dual-buffer (red/blue) sliding window approach:
/// - Two buffers (slots) track current and previous time windows
/// - Buffers swap atomically at each interval boundary
/// - Previous buffer is cleared when it becomes current
/// - Provides smooth rate estimation without spikes at boundaries
///
/// # Thread Safety
///
/// Lock-free implementation using atomic operations. Safe to use concurrently
/// from multiple threads without external synchronization.
///
/// # Memory Usage
///
/// Approximately 64 KB per Rate instance (2 × 32 KB for dual buffers)
pub struct Rate {
    // 2 slots so that we use one to collect the current events and the other to report rate
    red_slot: Estimator,
    blue_slot: Estimator,
    red_or_blue: AtomicBool, // true: the current slot is red, otherwise blue
    start: Instant,
    reset_interval_ms: u64, // the time interval to reset `current` and move it to `previous`
    last_reset_time: AtomicU64, // the timestamp in ms since `start`
    interval: Duration,
}

// Default configuration for Count-Min Sketch
// These values provide good balance between memory usage and accuracy
const HASHES: usize = 4;
const SLOTS: usize = 1024; // This value can be lower if interval is short (key cardinality is low)

impl Rate {
    /// Create a new `Rate` with the given interval.
    ///
    /// # Example
    /// ```ignore
    /// use std::time::Duration;
    /// let rate = Rate::new(Duration::from_secs(1)); // 1 second window
    /// ```
    pub fn new(interval: std::time::Duration) -> Self {
        Rate::new_with_estimator_config(interval, HASHES, SLOTS)
    }

    /// Create a new `Rate` with the given interval and Estimator config with the given amount of hashes and columns (slots).
    ///
    /// This is useful for tuning memory vs accuracy trade-offs.
    ///
    /// # Parameters
    /// - `interval`: Time window for rate calculation
    /// - `hashes`: Number of hash functions (more = more accurate)
    /// - `slots`: Number of counters per hash (more = less collision)
    #[inline]
    pub fn new_with_estimator_config(
        interval: std::time::Duration,
        hashes: usize,
        slots: usize,
    ) -> Self {
        Rate {
            red_slot: Estimator::new(hashes, slots),
            blue_slot: Estimator::new(hashes, slots),
            red_or_blue: AtomicBool::new(true),
            start: Instant::now(),
            reset_interval_ms: interval.as_millis() as u64,
            last_reset_time: AtomicU64::new(0),
            interval,
        }
    }

    fn current(&self, red_or_blue: bool) -> &Estimator {
        if red_or_blue {
            &self.red_slot
        } else {
            &self.blue_slot
        }
    }

    fn previous(&self, red_or_blue: bool) -> &Estimator {
        if red_or_blue {
            &self.blue_slot
        } else {
            &self.red_slot
        }
    }

    fn red_or_blue(&self) -> bool {
        self.red_or_blue.load(Ordering::SeqCst)
    }

    /// Return the per second rate estimation.
    ///
    /// This is the average rate of the latest completed period of length `interval`.
    ///
    /// # Example
    /// ```ignore
    /// let rate = Rate::new(Duration::from_secs(1));
    /// rate.observe(&"user-123", 5);
    /// // ... after 1 second ...
    /// assert_eq!(rate.rate(&"user-123"), 5.0); // 5 requests per second
    /// ```
    pub fn rate<T: Hash>(&self, key: &T) -> f64 {
        let past_ms = self.maybe_reset();
        if past_ms >= self.reset_interval_ms.saturating_mul(2) {
            // already missed 2 intervals, no data, just report 0 as a short cut
            return 0f64;
        }

        self.previous(self.red_or_blue()).get(key) as f64 * 1000.0 / self.reset_interval_ms as f64
    }

    /// Get the configured time interval for this rate tracker.
    ///
    /// # Returns
    /// The Duration representing the time window for rate tracking
    ///
    /// # Example
    /// ```ignore
    /// let rate = Rate::new(Duration::from_secs(1));
    /// assert_eq!(rate.interval(), Duration::from_secs(1));
    /// ```
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Report new events and return number of events seen so far in the current interval.
    ///
    /// This is the primary method used for rate limiting - call it for each event
    /// and check if the returned value exceeds your limit.
    ///
    /// # Parameters
    /// - `key`: Identifier for the entity being tracked (e.g., IP address, API key)
    /// - `events`: Number of events to add (typically 1)
    ///
    /// # Returns
    /// The total number of events for this key in the current time window
    ///
    /// # Example
    /// ```ignore
    /// let rate = Rate::new(Duration::from_secs(1));
    /// let count = rate.observe(&"192.168.1.1", 1);
    /// if count > 100 {
    ///     println!("Rate limit exceeded!");
    /// }
    /// ```
    pub fn observe<T: Hash>(&self, key: &T, events: isize) -> isize {
        self.maybe_reset();
        self.current(self.red_or_blue()).incr(key, events)
    }

    // reset if needed, return the time since last reset for other fn to use
    fn maybe_reset(&self) -> u64 {
        let now = Instant::now().duration_since(self.start).as_millis() as u64;
        let last_reset = self.last_reset_time.load(Ordering::SeqCst);
        let past_ms = now.saturating_sub(last_reset);

        if past_ms < self.reset_interval_ms {
            // no need to reset
            return past_ms;
        }
        let red_or_blue = self.red_or_blue();
        match self.last_reset_time.compare_exchange(
            last_reset,
            now,
            Ordering::SeqCst,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // first clear the previous slot
                self.previous(red_or_blue).reset();
                // then flip the flag to tell others to use the reset slot
                self.red_or_blue.store(!red_or_blue, Ordering::SeqCst);
                // if current time is beyond 2 intervals, the data stored in the previous slot
                // is also stale, we should clear that too
                if now.saturating_sub(last_reset) >= self.reset_interval_ms.saturating_mul(2) {
                    // Note that this is the previous one now because we just flipped self.red_or_blue
                    self.current(red_or_blue).reset();
                }
            }
            Err(new) => {
                // another thread beat us to it
                if new < now.saturating_sub(1000) {
                    tracing::warn!(
                        "Rate limiter timestamp inconsistency detected: new={}, now={}, diff={}ms",
                        new,
                        now,
                        now.saturating_sub(new)
                    );
                }
            }
        }

        past_ms
    }
}
