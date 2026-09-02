use aya::maps::{Array, Map, MapData};
use std::path::Path;

use crate::pin;
use crate::EbpfError;

/// Snapshot of the pinned `capture_state` array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureState {
    pub generation: u64,
    pub lifecycle: u64,
    pub boot_id: u64,
}

impl CaptureState {
    pub fn capturing(boot_id: u64, generation: u64) -> Self {
        Self { generation, lifecycle: pin::CAPTURE_LIFECYCLE_CAPTURING, boot_id }
    }

    pub fn is_draining(self) -> bool {
        self.lifecycle == pin::CAPTURE_LIFECYCLE_DRAINING
    }

    pub fn is_published(self) -> bool {
        self.boot_id != 0
    }

    /// Whether the agent holding `boot_id` is the one that published this state.
    ///
    /// Guards every partial write: a newer agent may have taken the pin over, and writing to it
    /// from the outgoing process would either resurrect a stale lifecycle or mark a healthy
    /// agent as draining, taking every proxy on the node out of the load balancer.
    ///
    /// An unpublished pin (`boot_id == 0`) belongs to nobody, so a caller that somehow carries a
    /// zero id does not own it either.
    pub fn owned_by(self, boot_id: u64) -> bool {
        self.is_published() && self.boot_id == boot_id
    }
}

/// Draw a non-zero boot id so `0` stays the "never written / legacy agent" sentinel.
pub fn new_agent_boot_id() -> Result<u64, EbpfError> {
    let id = super::seed::random_seed()?;
    Ok(if id == 0 { 1 } else { id })
}

pub fn read_capture_state(base_path: &str) -> Result<CaptureState, EbpfError> {
    let path = pin::capture_state_path(base_path);
    let map = Map::Array(open_data(&path)?);
    let array = Array::<_, u64>::try_from(&map)
        .map_err(|source| EbpfError::FromPin { path: path.display().to_string(), source })?;
    Ok(CaptureState {
        generation: array
            .get(&pin::CAPTURE_STATE_SLOT_GENERATION, 0)
            .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?,
        lifecycle: array
            .get(&pin::CAPTURE_STATE_SLOT_LIFECYCLE, 0)
            .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?,
        boot_id: array
            .get(&pin::CAPTURE_STATE_SLOT_BOOT_ID, 0)
            .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?,
    })
}

pub fn write_capture_state(base_path: &str, state: CaptureState) -> Result<(), EbpfError> {
    let path = pin::capture_state_path(base_path);
    let mut map = Map::Array(open_data(&path)?);
    let mut array = Array::<_, u64>::try_from(&mut map)
        .map_err(|source| EbpfError::FromPin { path: path.display().to_string(), source })?;
    array
        .set(pin::CAPTURE_STATE_SLOT_GENERATION, state.generation, 0)
        .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?;
    array
        .set(pin::CAPTURE_STATE_SLOT_LIFECYCLE, state.lifecycle, 0)
        .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?;
    array
        .set(pin::CAPTURE_STATE_SLOT_BOOT_ID, state.boot_id, 0)
        .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?;
    Ok(())
}

/// Bump the heartbeat, writing `generation` only.
///
/// Rewriting the whole snapshot here would push a stale `lifecycle` and `boot_id` back over
/// whatever a newer agent published, and this runs every `HUGINN_EBPF_HEARTBEAT_SECS`.
///
/// Returns the generation now on the pin; no-op unless `boot_id` still owns it.
pub fn bump_capture_generation(base_path: &str, boot_id: u64) -> Result<u64, EbpfError> {
    let state = read_capture_state(base_path)?;
    if !state.owned_by(boot_id) {
        return Ok(state.generation);
    }
    let generation = state.generation.wrapping_add(1);
    set_capture_slot(base_path, pin::CAPTURE_STATE_SLOT_GENERATION, generation)?;
    Ok(generation)
}

/// Announce drain so the proxy capture gate reports `capture_draining`.
///
/// Writes `lifecycle` only, and only while `boot_id` still owns the pin: on a rollout the next
/// agent may already have published `capturing`, and marking that one draining would 503 every
/// proxy on the node while capture is healthy.
///
/// Returns whether the announcement was written.
pub fn publish_capture_draining(base_path: &str, boot_id: u64) -> Result<bool, EbpfError> {
    if !read_capture_state(base_path)?.owned_by(boot_id) {
        return Ok(false);
    }
    set_capture_slot(
        base_path,
        pin::CAPTURE_STATE_SLOT_LIFECYCLE,
        pin::CAPTURE_LIFECYCLE_DRAINING,
    )?;
    Ok(true)
}

fn set_capture_slot(base_path: &str, slot: u32, value: u64) -> Result<(), EbpfError> {
    let path = pin::capture_state_path(base_path);
    let mut map = Map::Array(open_data(&path)?);
    let mut array = Array::<_, u64>::try_from(&mut map)
        .map_err(|source| EbpfError::FromPin { path: path.display().to_string(), source })?;
    array
        .set(slot, value, 0)
        .map_err(|source| EbpfError::MapInfo { path: path.display().to_string(), source })?;
    Ok(())
}

fn open_data(path: &Path) -> Result<MapData, EbpfError> {
    MapData::from_pin(path)
        .map_err(|e| EbpfError::FromPin { path: path.display().to_string(), source: e })
}
