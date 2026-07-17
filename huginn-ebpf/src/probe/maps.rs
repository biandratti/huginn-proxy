use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aya::maps::{MapData, MapInfo};
use tracing::{info, warn};

use crate::pin;
use crate::EbpfError;

use super::EbpfProbe;

impl EbpfProbe {
    /// Remove pinned map files.
    ///
    /// Not part of the normal shutdown path: pins are intentionally left in
    /// place so the next agent instance reuses the same maps (see
    /// [`EbpfProbe::new`]). Exposed for manual cleanup / tests.
    pub fn unpin_maps(base_path: &str) {
        remove_all_pins(base_path);
        warn!(base_path, "BPF map pins removed");
    }
}

/// Ensure the pin directory exists with permissions the proxy can traverse, and
/// drop any stale pins whose SYN map capacity no longer matches the requested `syn_map_max_entries`.
///
/// Because `aya` reuses an existing pin as-is (without validating its
/// attributes), a capacity change would otherwise be silently ignored.
pub(super) fn prepare_pins(base_path: &str, syn_map_max_entries: u32) -> Result<(), EbpfError> {
    let base = Path::new(base_path);
    std::fs::create_dir_all(base)
        .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;
    if let Some(parent) = base.parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;

    if syn_pin_capacity_mismatch(pin::syn_map_v4_path(base_path), syn_map_max_entries)
        || syn_pin_capacity_mismatch(pin::syn_map_v6_path(base_path), syn_map_max_entries)
    {
        info!(
            base_path,
            syn_map_max_entries, "existing SYN map pins have a different capacity; recreating"
        );
        remove_all_pins(base_path);
    }
    Ok(())
}

/// Relax pin file permissions so the non-root proxy process can open them.
///
/// `BPF_OBJ_GET` checks inode permissions (`MAY_READ | MAY_WRITE`) and `aya`
/// creates pins as `0600 root:root`.
pub(super) fn chmod_pins(base_path: &str) {
    for name in pin::ALL_NAMES {
        let _ = std::fs::set_permissions(
            Path::new(base_path).join(name),
            std::fs::Permissions::from_mode(0o666),
        );
    }
}

/// `true` if a pin exists at `path` but its `max_entries` differs from
/// `expected`. A missing or unreadable pin is treated as compatible (the loader
/// will create it).
fn syn_pin_capacity_mismatch(path: PathBuf, expected: u32) -> bool {
    match MapInfo::from_pin(&path) {
        Ok(info) => info.max_entries() != expected,
        Err(_) => false,
    }
}

fn remove_all_pins(base_path: &str) {
    for name in pin::ALL_NAMES {
        let _ = std::fs::remove_file(Path::new(base_path).join(name));
    }
}

/// Open a pinned map by path, mapping open failures to [`EbpfError::FromPin`].
pub(super) fn open_pinned_map(path: PathBuf) -> Result<MapData, EbpfError> {
    MapData::from_pin(&path)
        .map_err(|e| EbpfError::FromPin { path: path.display().to_string(), source: e })
}

/// Return the kernel ID of the BPF map currently pinned at `path`.
pub(super) fn pinned_map_id(path: PathBuf) -> Result<u32, EbpfError> {
    MapInfo::from_pin(&path)
        .map(|info| info.id())
        .map_err(|e| EbpfError::MapInfo { path: path.display().to_string(), source: e })
}

/// Return the kernel ID of an already-open BPF map.
pub(super) fn open_map_id(map: &MapData, path: PathBuf) -> Result<u32, EbpfError> {
    map.info()
        .map(|info| info.id())
        .map_err(|e| EbpfError::MapInfo { path: path.display().to_string(), source: e })
}

/// Return the capacity (`max_entries`) of an already-open BPF map.
pub(super) fn open_map_max_entries(map: &MapData, path: PathBuf) -> Result<u32, EbpfError> {
    map.info()
        .map(|info| info.max_entries())
        .map_err(|e| EbpfError::MapInfo { path: path.display().to_string(), source: e })
}
