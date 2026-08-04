#![no_std]
#![forbid(unsafe_code)]

//! Per-source-IP SYN rate limiter for the huginn eBPF SYN-capture programs.
//!
//! Counts each source IP's recent SYNs and reports when one goes over its limit. It never stores
//! IPs individually - it hashes each into a small fixed-size grid of counters (a Count-Min
//! Sketch). Memory is constant, so it holds up even under millions of spoofed source IPs - but
//! accuracy does not: the grid is only [`HASHES`] x [`SLOTS`] counters, so a flood spread across
//! enough source IPs saturates every cell, and then every source reads over-limit and stops being
//! captured, legitimate ones included.
//!
//! How it works:
//!
//! - **The grid**: [`HASHES`] rows x [`SLOTS`] columns. Each IP hashes to one cell per row (4
//!   total); its count is the smallest of those 4 cells. Two IPs can share a cell, which only
//!   ever inflates a count, so a real flood is never missed, but an innocent IP may occasionally
//!   be blocked. More [`SLOTS`] = fewer collisions, more memory.
//! - **Two grids (sliding window)**: we keep both the current window's counters and the previous
//!   window's, flipping between two grids each window. A source's estimate blends its current
//!   count with its previous-window count, decayed linearly by how much of the current window is
//!   still left. This approximates a sliding window, so a flood straddling a window boundary
//!   can't reset its way under the limit (the classic fixed-window boundary burst). The two-buffer
//!   blend is adapted from Cloudflare's [`pingora-limits`
//!   `Rate`](https://github.com/cloudflare/pingora/blob/main/pingora-limits/src/rate.rs), which
//!   swaps two `Estimator`s per interval and combines them the same way. Everything past that
//!   pattern is our own: the Count-Min Sketch hashing/layout, `u16` counters, per-CPU BPF map
//!   fit, and the integer-only fixed-point decay below (`pingora-limits` uses `f64` and isn't
//!   `no_std`, so its arithmetic doesn't carry over as-is to eBPF).
//! - **Integers only**: eBPF has no floats, so the decay is integer math:
//!   `estimate = current + previous * remaining_ns / window_ns`.
//! - **Keyed hashing**: which cells an IP lands in depends on a random `seed` the loader picks
//!   per load, mixed in by [`key_v4`]/[`key_v6`]. Without it an attacker can compute a victim's
//!   cells offline and flood them (targeted suppression). [`SketchKey`] can only come from those
//!   two functions, so a raw address can't reach the grid unkeyed.
//!
//! **Concurrency**: each CPU has its own copy (stored in a per-CPU BPF map), so nothing is shared
//! and no locks or atomics are needed. Downside: the limit is per-CPU, not global.
//!
//! [`Sketch`] is `#[repr(C)]`, so it sits directly in one BPF map slot and is edited in place.

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

/// One salt number per row, used to turn a key into a column index. Each is a well-known
/// constant borrowed from other hash functions, chosen only because it mixes bits well.
///
/// Public, no secrecy here - unpredictability comes from the per-load seed in the key
/// ([`key_v4`]/[`key_v6`]). These just decorrelate the rows.
const SALTS: [u64; HASHES] = [
    0x9E37_79B9_7F4A_7C15, // from the golden ratio
    0xC2B2_AE3D_27D4_EB4F, // from xxHash
    0x1656_67B1_9E37_79F9, // from xxHash
    0xFF51_AFD7_ED55_8CCD, // from MurmurHash3
];

/// Scramble one 64-bit value into another (the SplitMix64 finalizer). A bijection with full bit
/// diffusion, so an IP's cells stay unpredictable once seeded. No division or 128-bit math, so
/// it lowers cleanly on BPF.
#[inline(always)]
fn mix64(x: u64) -> u64 {
    let mut h = x ^ x.wrapping_shr(30);
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h.wrapping_shr(27);
    h = h.wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^ h.wrapping_shr(31)
}

/// A source address already mixed with the per-load seed, ready to index the grid.
///
/// Only [`key_v4`]/[`key_v6`] build one, so [`Sketch::observe_over_limit`] can't be handed an
/// unseeded address (see the keyed-hashing note above).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct SketchKey(u64);

/// Key an IPv4 source address with `seed`.
///
/// The mixer is a bijection, so two distinct addresses never share a key (they can still share
/// a *cell* - inherent to the sketch - but which cells is unknown without the seed).
#[inline(always)]
pub fn key_v4(saddr: u32, seed: u64) -> SketchKey {
    SketchKey(mix64(seed ^ (saddr as u64)))
}

/// Key a 16-byte IPv6 source address with `seed`.
///
/// Halves are chained through the mixer, not XOR-folded. A plain `hi ^ lo` fold gives an exact
/// key collision for free (`lo = victim_hi ^ victim_lo ^ attacker_hi`, sourceable from one /64);
/// chaining keeps the low half injective, closing that off.
#[inline(always)]
pub fn key_v6(addr: [u8; 16], seed: u64) -> SketchKey {
    let mut hi = [0u8; 8];
    let mut lo = [0u8; 8];
    hi.copy_from_slice(&addr[..8]);
    lo.copy_from_slice(&addr[8..]);
    let h = mix64(seed ^ u64::from_ne_bytes(hi));
    SketchKey(mix64(h ^ u64::from_ne_bytes(lo)))
}

/// Pick the column for `key` in row `row`: multiply by the row's salt, keep the top bits.
/// The `& (SLOTS - 1)` keeps the index in range (0..SLOTS) and proves it to the BPF verifier.
#[inline(always)]
fn column(key: u64, row: usize) -> usize {
    let h = key.wrapping_mul(SALTS[row]);
    ((h >> (64 - SLOTS_BITS)) as usize) & (SLOTS - 1)
}

/// The column each row picks for `key` - one index per row, [`HASHES`] in total.
#[inline(always)]
pub fn cell_indices(key: SketchKey) -> [usize; HASHES] {
    let mut cols = [0usize; HASHES];
    let mut row = 0;
    while row < HASHES {
        cols[row] = column(key.0, row);
        row = row.saturating_add(1);
    }
    cols
}

/// The counter grid, in two copies so we can swap between them each window.
/// `#[repr(C)]` gives it a fixed, predictable memory layout so it can be stored directly as
/// the value of a single-entry BPF `PerCpuArray` map and edited in place through a raw pointer.
/// Each CPU owns its own copy, so plain (non-atomic) fields are safe: no CPU ever touches
/// another CPU's grid.
#[repr(C)]
pub struct Sketch {
    /// Both grids back to back in one array: grid `s` occupies `[s*SLOT_LEN, (s+1)*SLOT_LEN)`,
    /// and within a grid, row `j` occupies `[j*SLOTS, (j+1)*SLOTS)`. `u16` (saturating at 65535)
    /// halves the map size vs `u32` so `SLOTS = 1024` fits the per-CPU limit; the ceiling is far
    /// above any sane per-window threshold, and a saturated cell stays "over limit" regardless.
    pub counters: [u16; TOTAL_COUNTERS],
    /// Timestamp (nanoseconds) when the current window started.
    pub last_reset_ns: u64,
    /// Which grid holds the current window: 0 or 1. The other grid holds the previous window,
    /// which decays into the estimate until it is cleared and reused as the next current grid.
    pub active_slot: u32,
    /// Unused filler so the struct size is a clean multiple of 8 bytes.
    pub _pad: u32,
}

// A `PerCpuArray<Sketch>` map value must fit the kernel per-CPU allocation limit
// (`PCPU_MIN_UNIT_SIZE` = 32 KiB) or map creation fails at load with `E2BIG`. Enforce it at
// compile time so growing `SLOTS`/`HASHES` can't silently reintroduce the failure.
const _: () = assert!(
    core::mem::size_of::<Sketch>() <= 32 * 1024,
    "Sketch exceeds the BPF per-CPU map value limit (32 KiB); reduce SLOTS or HASHES",
);

impl Sketch {
    /// Every counter at 0, no window started yet.
    pub const fn new() -> Self {
        Self { counters: [0u16; TOTAL_COUNTERS], last_reset_ns: 0, active_slot: 0, _pad: 0 }
    }

    /// Set every counter in one grid back to 0.
    #[inline(always)]
    fn clear_slot(&mut self, slot: u32) {
        let base = (slot as usize).wrapping_mul(SLOT_LEN);
        let mut i = 0;
        while i < SLOT_LEN {
            // Bitmask just proves to the BPF verifier that this index can't go out of bounds.
            self.counters[base.saturating_add(i) & (TOTAL_COUNTERS - 1)] = 0;
            i = i.saturating_add(1);
        }
    }

    /// Advance the window once `window_ns` has elapsed: flip grids so the old current becomes the
    /// previous window, clearing the grid we flip into (it's two windows old). If 2+ windows
    /// elapsed, the grid we leave is stale too, so clear both and start fresh.
    ///
    /// `window_ns == 0` means "never rotate" (tests).
    #[inline(always)]
    fn maybe_rotate(&mut self, now_ns: u64, window_ns: u64) {
        if window_ns == 0 {
            return;
        }
        let elapsed = now_ns.saturating_sub(self.last_reset_ns);
        if elapsed < window_ns {
            return;
        }
        let next = self.active_slot ^ 1;
        self.clear_slot(next);
        // Idle for 2+ windows: the grid we are leaving is stale too, so clear it instead of letting
        // it decay in as "previous". `elapsed - window >= window` is the same test as
        // `elapsed >= 2*window` (`elapsed >= window` holds here), but avoids a runtime `* 2`, which
        // lowers to a 128-bit checked multiply calling `__multi3`, unlinkable on BPF.
        if elapsed.saturating_sub(window_ns) >= window_ns {
            self.clear_slot(self.active_slot);
        }
        self.active_slot = next;
        self.last_reset_ns = now_ns;
    }

    /// Count one more SYN from `key` and say whether that IP is now over `threshold` (i.e. its
    /// SYN should be skipped, not captured - the packet is never dropped). The estimate is the
    /// current window's count plus the previous window's count
    /// decayed by how much of the current window is left, approximating a sliding window:
    /// `estimate = current + previous * remaining_ns / window_ns`. Allows up to `threshold`
    /// before going over.
    #[inline(always)]
    pub fn observe_over_limit(
        &mut self,
        key: SketchKey,
        now_ns: u64,
        window_ns: u64,
        threshold: u32,
    ) -> bool {
        self.maybe_rotate(now_ns, window_ns);

        let active = self.active_slot as usize;
        let base = active.wrapping_mul(SLOT_LEN);
        let prev_base = (active ^ 1).wrapping_mul(SLOT_LEN);
        let cols = cell_indices(key);

        // Increment the current grid and read the previous grid for the same cells in one pass.
        let mut curr_min = u16::MAX;
        let mut prev_min = u16::MAX;
        let mut row = 0;
        while row < HASHES {
            let off = row.wrapping_mul(SLOTS).saturating_add(cols[row]);

            let idx = base.saturating_add(off) & (TOTAL_COUNTERS - 1);
            let c = self.counters[idx].saturating_add(1);
            self.counters[idx] = c;
            if c < curr_min {
                curr_min = c;
            }

            let pidx = prev_base.saturating_add(off) & (TOTAL_COUNTERS - 1);
            let p = self.counters[pidx];
            if p < prev_min {
                prev_min = p;
            }

            row = row.saturating_add(1);
        }

        // window_ns == 0 (tests): no rotation, no previous-window blend.
        if window_ns == 0 {
            return u32::from(curr_min) > threshold;
        }

        // Decay the previous window by `remaining / window`. BPF `--cpu generic` has no native
        // 64-bit divide (LLVM lowers it via `__multi3`, which can't be linked), but 64-bit
        // multiply and 32-bit divide are fine. So shift `window`/`remaining` right by the same
        // amount (ratio-preserving) until they fit in 32 bits, then take an 8-bit fraction.
        let elapsed = now_ns.saturating_sub(self.last_reset_ns);
        let remaining = window_ns.saturating_sub(elapsed);
        // Constant-bounded trip count (<= 64, with a break) so the BPF verifier can prove the
        // loop terminates; a plain `while w > CONST` is data-dependent and can be rejected.
        let mut w = window_ns;
        let mut r = remaining;
        let mut i = 0u32;
        while i < 64 {
            if w <= 0x007F_FFFF {
                break;
            }
            w = w.wrapping_shr(1);
            r = r.wrapping_shr(1);
            i = i.wrapping_add(1);
        }
        // `w` is in `1..=0x7F_FFFF` (window_ns > 0 here) and `r <= w`, so `frac` is in `0..=256`:
        // 256 at a window start (full previous window), 0 as it runs out.
        let frac = (r as u32)
            .wrapping_shl(8)
            .checked_div(w as u32)
            .unwrap_or(0);
        // prev_min (<= u16::MAX) * frac (<= 256) fits in u64; `>> 8` undoes the fixed-point scale.
        let prev_contrib = (prev_min as u64).wrapping_mul(frac as u64).wrapping_shr(8);
        let estimate = (curr_min as u64).saturating_add(prev_contrib);
        estimate > threshold as u64
    }
}

impl Default for Sketch {
    fn default() -> Self {
        Self::new()
    }
}
