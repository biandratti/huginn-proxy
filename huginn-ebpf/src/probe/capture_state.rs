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

pub fn bump_capture_generation(base_path: &str) -> Result<u64, EbpfError> {
    let mut state = read_capture_state(base_path)?;
    state.generation = state.generation.wrapping_add(1);
    write_capture_state(base_path, state)?;
    Ok(state.generation)
}

fn open_data(path: &Path) -> Result<MapData, EbpfError> {
    MapData::from_pin(path)
        .map_err(|e| EbpfError::FromPin { path: path.display().to_string(), source: e })
}
