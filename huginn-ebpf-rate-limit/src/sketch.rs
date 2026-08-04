//! Count-Min Sketch implementation. See the crate README for the algorithm description.

use crate::{HASHES, SLOTS, SLOTS_BITS, SLOT_LEN, TOTAL_COUNTERS};

/// A source address already mixed with the per-load seed.
///
/// Only [`key_v4`]/[`key_v6`] build one, so [`Sketch::observe_over_limit`] can't be handed an
/// unseeded address (see the keyed-hashing note in the README).
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

/// Key a 16-byte IPv6 source address with `seed`, using only the /64 prefix (high 8 bytes).
///
/// The low 64 bits (interface identifier) are free for whoever holds the /64 to pick, so keying
/// on them lets one delegated /64 spray unlimited distinct keys and never hit the sketch budget.
/// Keying on the prefix instead matches the actual allocation boundary: a /64 shares one budget,
/// however many addresses inside it are used.
#[inline(always)]
pub fn key_v6(addr: [u8; 16], seed: u64) -> SketchKey {
    let mut hi = [0u8; 8];
    hi.copy_from_slice(&addr[..8]);
    SketchKey(mix64(seed ^ u64::from_ne_bytes(hi)))
}

/// One salt number per row, used to turn a key into a column index. Each is a well-known
/// constant borrowed from other hash functions, chosen only because it mixes bits well.
///
/// Public, no secrecy here - unpredictability comes from the per-load seed in the key
/// ([`crate::key_v4`]/[`crate::key_v6`]). These just decorrelate the rows.
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
