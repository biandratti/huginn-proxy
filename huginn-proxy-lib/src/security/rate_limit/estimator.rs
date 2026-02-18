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

//! The estimator module contains a Count-Min Sketch type to help estimate the frequency of an item.
//!
//! This is adapted from Pingora's implementation for use in Huginn Proxy.

use crate::security::rate_limit::hash;
use ahash::RandomState;
use std::hash::Hash;
use std::sync::atomic::{AtomicIsize, Ordering};

/// An implementation of a lock-free count–min sketch estimator. See the [wikipedia] page for more
/// information.
///
/// Count-Min Sketch is a probabilistic data structure that serves as a frequency table of events.
/// It uses multiple hash functions to provide an estimate of how many times an event has occurred.
///
/// [wikipedia]: https://en.wikipedia.org/wiki/Count%E2%80%93min_sketch
pub struct Estimator {
    estimator: Box<[(Box<[AtomicIsize]>, RandomState)]>,
}

impl Estimator {
    /// Create a new `Estimator` with the given amount of hashes and columns (slots).
    ///
    /// # Parameters
    /// - `hashes`: Number of hash functions (more = more accurate, typically 4)
    /// - `slots`: Number of counters per hash function (more = less collision, typically 1024)
    ///
    /// # Memory Usage
    /// Total memory = hashes × slots × 8 bytes
    /// Example: 4 hashes × 1024 slots × 8 bytes = 32 KB
    pub fn new(hashes: usize, slots: usize) -> Self {
        Self {
            estimator: (0..hashes)
                .map(|_| (0..slots).map(|_| AtomicIsize::new(0)).collect::<Vec<_>>())
                .map(|slot| (slot.into_boxed_slice(), RandomState::new()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    /// Increment `key` by the value given. Return the new estimated value as a result.
    ///
    /// Note: overflow can happen. When some of the internal counters overflow, a negative number
    /// will be returned. It is up to the caller to catch and handle this case.
    ///
    /// # Example
    /// ```ignore
    /// # use huginn_proxy_lib::security::rate_limit::estimator::Estimator;
    /// let est = Estimator::new(4, 1024);
    /// let count = est.incr("user-123", 1);
    /// assert_eq!(count, 1);
    /// ```
    pub fn incr<T: Hash>(&self, key: T, value: isize) -> isize {
        self.estimator
            .iter()
            .fold(isize::MAX, |min, (slot, hasher)| {
                let hash = hash(&key, hasher) as usize;
                // In practice, slot.len() is always > 0 (initialized with SLOTS constant)
                let index = hash.checked_rem(slot.len()).unwrap_or_default();
                let counter = &slot[index];
                let current = counter.fetch_add(value, Ordering::Relaxed);
                std::cmp::min(min, current.saturating_add(value))
            })
    }

    /// Decrement `key` by the value given.
    ///
    /// Note: This is rarely used in rate limiting but provided for completeness.
    #[allow(dead_code)]
    pub fn decr<T: Hash>(&self, key: T, value: isize) {
        for (slot, hasher) in self.estimator.iter() {
            let hash = hash(&key, hasher) as usize;
            let index = hash.checked_rem(slot.len()).unwrap_or_default();
            let counter = &slot[index];
            counter.fetch_sub(value, Ordering::Relaxed);
        }
    }

    /// Get the estimated frequency of `key`.
    ///
    /// Returns the minimum count across all hash functions, which provides
    /// the best estimate (may over-estimate, never under-estimates).
    pub fn get<T: Hash>(&self, key: T) -> isize {
        self.estimator
            .iter()
            .fold(isize::MAX, |min, (slot, hasher)| {
                let hash = hash(&key, hasher) as usize;
                let index = hash.checked_rem(slot.len()).unwrap_or_default();
                let counter = &slot[index];
                let current = counter.load(Ordering::Relaxed);
                std::cmp::min(min, current)
            })
    }

    /// Reset all values inside this `Estimator`.
    ///
    /// This is typically called when switching windows in the rate tracker.
    pub fn reset(&self) {
        self.estimator.iter().for_each(|(slot, _)| {
            slot.iter()
                .for_each(|counter| counter.store(0, Ordering::Relaxed))
        });
    }
}
