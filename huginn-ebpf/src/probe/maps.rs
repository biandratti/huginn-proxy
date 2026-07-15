use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aya::maps::{MapData, MapInfo};
use tracing::info;

use crate::pin;
use crate::EbpfError;

use super::{EbpfProbe, ProbeInner};

impl EbpfProbe {
    /// Pin the BPF maps to `base_path` so other processes can open them.
    ///
    /// Creates the directory if it does not exist. Removes stale pins from a
    /// previous run before pinning. Only valid in embedded mode.
    pub fn pin_maps(&mut self, base_path: &str) -> Result<(), EbpfError> {
        let base = Path::new(base_path);
        std::fs::create_dir_all(base)
            .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;
        if let Some(parent) = base.parent() {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| EbpfError::PinDir { path: base_path.to_string(), source: e })?;

        let ebpf = match &mut self.inner {
            ProbeInner::Embedded { ebpf } => ebpf,
            ProbeInner::Pinned(_) => return Ok(()),
        };

        let syn_path_v4 = pin::syn_map_v4_path(base_path);
        let syn_path_v6 = pin::syn_map_v6_path(base_path);
        let counter_path = pin::counter_path(base_path);
        let insert_failures_v4_path = pin::insert_failures_v4_path(base_path);
        let syn_captured_v4_path = pin::syn_captured_v4_path(base_path);
        let syn_malformed_v4_path = pin::syn_malformed_v4_path(base_path);
        let insert_failures_v6_path = pin::insert_failures_v6_path(base_path);
        let syn_captured_v6_path = pin::syn_captured_v6_path(base_path);
        let syn_malformed_v6_path = pin::syn_malformed_v6_path(base_path);

        // Remove stale pins from a previous agent instance.
        let _ = std::fs::remove_file(&syn_path_v4);
        let _ = std::fs::remove_file(&syn_path_v6);
        let _ = std::fs::remove_file(&counter_path);
        let _ = std::fs::remove_file(&insert_failures_v4_path);
        let _ = std::fs::remove_file(&syn_captured_v4_path);
        let _ = std::fs::remove_file(&syn_malformed_v4_path);
        let _ = std::fs::remove_file(&insert_failures_v6_path);
        let _ = std::fs::remove_file(&syn_captured_v6_path);
        let _ = std::fs::remove_file(&syn_malformed_v6_path);

        let syn_map_v4 = ebpf
            .map_mut(pin::SYN_MAP_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_map_v4
            .pin(&syn_path_v4)
            .map_err(|e| EbpfError::Pin { name: pin::SYN_MAP_V4_NAME.to_string(), source: e })?;

        let syn_map_v6 = ebpf
            .map_mut(pin::SYN_MAP_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_map_v6
            .pin(&syn_path_v6)
            .map_err(|e| EbpfError::Pin { name: pin::SYN_MAP_V6_NAME.to_string(), source: e })?;

        let counter = ebpf
            .map_mut(pin::COUNTER_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        counter
            .pin(&counter_path)
            .map_err(|e| EbpfError::Pin { name: pin::COUNTER_NAME.to_string(), source: e })?;

        let insert_failures_v4 = ebpf
            .map_mut(pin::SYN_INSERT_FAILURES_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        insert_failures_v4
            .pin(&insert_failures_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_INSERT_FAILURES_V4_NAME.to_string(),
                source: e,
            })?;

        let syn_captured_v4 = ebpf
            .map_mut(pin::SYN_CAPTURED_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_captured_v4
            .pin(&syn_captured_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_CAPTURED_V4_NAME.to_string(),
                source: e,
            })?;

        let syn_malformed_v4 = ebpf
            .map_mut(pin::SYN_MALFORMED_V4_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_malformed_v4
            .pin(&syn_malformed_v4_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_MALFORMED_V4_NAME.to_string(),
                source: e,
            })?;

        let insert_failures_v6 = ebpf
            .map_mut(pin::SYN_INSERT_FAILURES_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        insert_failures_v6
            .pin(&insert_failures_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_INSERT_FAILURES_V6_NAME.to_string(),
                source: e,
            })?;

        let syn_captured_v6 = ebpf
            .map_mut(pin::SYN_CAPTURED_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_captured_v6
            .pin(&syn_captured_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_CAPTURED_V6_NAME.to_string(),
                source: e,
            })?;

        let syn_malformed_v6 = ebpf
            .map_mut(pin::SYN_MALFORMED_V6_NAME)
            .ok_or(EbpfError::ProgramNotFound)?;
        syn_malformed_v6
            .pin(&syn_malformed_v6_path)
            .map_err(|e| EbpfError::Pin {
                name: pin::SYN_MALFORMED_V6_NAME.to_string(),
                source: e,
            })?;

        // BPF_OBJ_GET checks inode permissions (MAY_READ | MAY_WRITE).
        // Pin files are created as 0600 root:root; open them to the non-root proxy process.
        let open_mode = std::fs::Permissions::from_mode(0o666);
        let _ = std::fs::set_permissions(&syn_path_v4, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_path_v6, open_mode.clone());
        let _ = std::fs::set_permissions(&counter_path, open_mode.clone());
        let _ = std::fs::set_permissions(&insert_failures_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_captured_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_malformed_v4_path, open_mode.clone());
        let _ = std::fs::set_permissions(&insert_failures_v6_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_captured_v6_path, open_mode.clone());
        let _ = std::fs::set_permissions(&syn_malformed_v6_path, open_mode);

        info!(base_path, "BPF maps pinned");
        Ok(())
    }

    /// Remove pinned map files. Called during agent shutdown for clean teardown.
    pub fn unpin_maps(base_path: &str) {
        let _ = std::fs::remove_file(pin::syn_map_v4_path(base_path));
        let _ = std::fs::remove_file(pin::syn_map_v6_path(base_path));
        let _ = std::fs::remove_file(pin::counter_path(base_path));
        let _ = std::fs::remove_file(pin::insert_failures_v4_path(base_path));
        let _ = std::fs::remove_file(pin::syn_captured_v4_path(base_path));
        let _ = std::fs::remove_file(pin::syn_malformed_v4_path(base_path));
        let _ = std::fs::remove_file(pin::insert_failures_v6_path(base_path));
        let _ = std::fs::remove_file(pin::syn_captured_v6_path(base_path));
        let _ = std::fs::remove_file(pin::syn_malformed_v6_path(base_path));
        info!(base_path, "BPF map pins removed");
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
