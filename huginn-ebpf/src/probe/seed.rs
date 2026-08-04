//! Random hash seed for the in-kernel SYN rate limiter.
//!
//! With a fixed, public hash an attacker can compute a chosen victim's grid cells offline and
//! flood them. A fresh random seed per load makes the mapping unknown outside the running
//! program, so a flood can't be aimed at anyone in particular.
//!
//! Only ever patched into the BPF program's `syn_rate_seed` global - never logged or exposed
//! through a map.

use crate::EbpfError;

/// Draw a fresh 64-bit hash seed.
///
/// Fails rather than falling back to a weak value - a predictable seed is worse than a load that
/// refuses to start.
pub fn random_seed() -> Result<u64, EbpfError> {
    Ok(getrandom::u64()?)
}
