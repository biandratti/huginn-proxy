use aya::maps::{Array, Map, MapData, PerCpuArray};

use crate::pin;

/// Read slot 0 of a single-entry `Array<u64>` counter map (used for the global tick).
pub(super) fn read_array_counter(map: &Map) -> Option<u64> {
    let array = Array::<_, u64>::try_from(map).ok()?;
    array.get(&0, 0).ok()
}

/// Read slot 0 of a single-entry `PerCpuArray<u64>` counter map, summing the per-CPU values.
///
/// The kernel increments a per-CPU slot (race-free); the meaningful total is the sum across CPUs.
pub(super) fn read_percpu_counter(map: &Map) -> Option<u64> {
    let array = PerCpuArray::<_, u64>::try_from(map).ok()?;
    let per_cpu = array.get(&0, 0).ok()?;
    Some(per_cpu.iter().fold(0u64, |acc, &v| acc.wrapping_add(v)))
}

fn read_percpu_counter_from_path(path: impl AsRef<std::path::Path>) -> Option<u64> {
    let data = MapData::from_pin(path.as_ref()).ok()?;
    read_percpu_counter(&Map::PerCpuArray(data))
}

/// Returns `true` when a map entry is too old to be trusted.
///
/// `stored_tick` is the global SYN counter at capture time; `current_tick` is the
/// counter now. An entry is stale when more than `2 x syn_map_max_entries` SYNs have
/// arrived since capture, enough to have evicted and reused the LRU slot once.
pub fn is_stale(stored_tick: u64, current_tick: u64, syn_map_max_entries: u32) -> bool {
    let threshold = u64::from(syn_map_max_entries).saturating_mul(2);
    current_tick.saturating_sub(stored_tick) > threshold
}

pub fn syn_insert_failures_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::insert_failures_v4_path(base_path))
}

pub fn syn_captured_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_captured_v4_path(base_path))
}

pub fn syn_malformed_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_malformed_v4_path(base_path))
}

pub fn syn_insert_failures_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::insert_failures_v6_path(base_path))
}

pub fn syn_captured_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_captured_v6_path(base_path))
}

pub fn syn_malformed_v6_count_from_path(base_path: &str) -> Option<u64> {
    read_percpu_counter_from_path(pin::syn_malformed_v6_path(base_path))
}
