#![no_std]
#![forbid(unsafe_code)]

//! Per-source-IP SYN rate limiter for the huginn eBPF SYN-capture programs.

mod sketch;

pub use sketch::{cell_indices, key_v4, key_v6, Sketch, SketchKey};

/// Number of rows in the grid (how many times each IP gets hashed).
pub const HASHES: usize = 4;

/// Number of columns per row. A power of two, so picking a column is just a bitmask.
///
/// Bounded by the per-CPU map value limit: `Sketch` (two grids of `HASHES * SLOTS` counters plus
/// metadata) must stay under the kernel's `PCPU_MIN_UNIT_SIZE` (32 KiB) or map creation fails
/// with `E2BIG`. Counters are [`u16`], so `HASHES = 4`, `SLOTS = 1024` fits in 16 KiB. See the
/// `size_of::<Sketch>` assert.
pub const SLOTS: usize = 1024;

// SLOTS must stay a power of two: the column-selection bitmask, SLOTS_BITS below, and the
// verifier-friendly index masks all depend on it.
const _: () = assert!(SLOTS.is_power_of_two(), "SLOTS must be a power of two");

/// `log2(SLOTS)`: how many top bits of the hash pick a column. Derived from `SLOTS` (valid because
/// `SLOTS` is a power of two), so it can never drift out of sync.
const SLOTS_BITS: u32 = SLOTS.trailing_zeros();

/// Counters in one grid (`HASHES * SLOTS`).
pub const SLOT_LEN: usize = HASHES * SLOTS;

/// Counters across both grids combined.
pub const TOTAL_COUNTERS: usize = SLOT_LEN * 2;

// The index masks below (`& (TOTAL_COUNTERS - 1)`) only *bound* an index while TOTAL_COUNTERS is a
// power of two; otherwise they silently alias one grid's cells onto the other's. That holds via
// SLOTS being a power of two and HASHES being one too, so assert it directly rather than relying
// on both.
const _: () =
    assert!(TOTAL_COUNTERS.is_power_of_two(), "the index masks require a power-of-two size");

/// Largest `threshold` [`Sketch::observe_over_limit`] can enforce.
///
/// Counters saturate at [`u16::MAX`], so one window's own count can never exceed a threshold at or
/// above that, and callers must reject larger values. Derived from the counter width, so widening
/// `counters` lifts it automatically.
pub const MAX_THRESHOLD: u32 = (u16::MAX as u32).saturating_sub(1);
