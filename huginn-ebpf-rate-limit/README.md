# huginn-ebpf-rate-limit

Per-source SYN rate limiter for the huginn eBPF SYN-capture programs: per-address for IPv4, per-/64
for IPv6.

Counts each source's recent SYNs and reports when one goes over its limit. It never stores
sources individually - it hashes each into a small fixed-size grid of counters (a Count-Min Sketch).
Memory is constant, so it holds up even under millions of spoofed source IPs - but accuracy does
not: the grid is only [`HASHES`](src/lib.rs) x [`SLOTS`](src/lib.rs) counters, so a flood spread
across enough source IPs saturates every cell, and then every source reads over-limit and stops
being captured, legitimate ones included.

## How it works

- **The grid**: `HASHES` rows x `SLOTS` columns. Each IP hashes to one cell per row (4 total);
  its count is the smallest of those 4 cells. Two IPs can share a cell, which only ever inflates
  a count, so a real flood is never missed, but an innocent IP may occasionally be blocked. More
  `SLOTS` = fewer collisions, more memory.
- **Two grids (sliding window)**: we keep both the current window's counters and the previous
  window's, flipping between two grids each window. A source's estimate blends its current count
  with its previous-window count, decayed linearly by how much of the current window is still
  left. This approximates a sliding window, so a flood straddling a window boundary can't reset
  its way under the limit (the classic fixed-window boundary burst). The two-buffer blend is
  adapted from Cloudflare's [`pingora-limits`
  `Rate`](https://github.com/cloudflare/pingora/blob/main/pingora-limits/src/rate.rs), which swaps
  two `Estimator`s per interval and combines them the same way. Everything past that pattern is
  our own: the Count-Min Sketch hashing/layout, `u16` counters, per-CPU BPF map fit, and the
  integer-only fixed-point decay below (`pingora-limits` uses `f64` and isn't `no_std`, so its
  arithmetic doesn't carry over as-is to eBPF).
- **Integers only**: eBPF has no floats, so the decay is integer math:
  `estimate = current + previous * remaining_ns / window_ns`.
- **Keyed hashing**: which cells a key lands in depends on a random `seed` the loader picks per
  load, mixed in by `key_v4`/`key_v6`. Without it an attacker can compute a victim's cells offline
  and flood them. `SketchKey` can only come from those two functions, so a raw address can't
  reach the grid unkeyed.
- **IPv6 is keyed by /64, not by full address**: the low 64 bits (interface identifier) are free
  for whoever holds the /64 to pick, at no allocation cost. Keying on the full address would let
  one delegated /64 spray unlimited distinct keys and never hit the budget. Keying on the prefix
  closes that off, at a cost: every address sharing a /64 also shares its budget, so one noisy
  device in a household or office can push the whole prefix over the limit. Acceptable because
  going over the limit only skips capture (fingerprinting); the packet is never dropped. It's also
  a partial fix, not a full one - a delegation bigger than /64 (/56, /48, a hosting /32) still
  gets one budget per /64 inside it, so the attacker's cost scales with prefix size, not address
  space.

**Concurrency**: each CPU has its own copy (stored in a per-CPU BPF map), so nothing is shared and
no locks or atomics are needed. Downside: the limit is per-CPU, not global.

`Sketch` is `#[repr(C)]`, so it sits directly in one BPF map slot and is edited in place.


Must compile for `bpfel-unknown-none` (the BPF target) and for the host (tests).
