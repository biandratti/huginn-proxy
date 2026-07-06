//! Loader-patched verbose-logging level for the capture datapath (the `aya-log` gate).
//!
//! Kept separate from the BPF maps/filters: this is a cross-cutting logging knob, not packet state.

/// Verbose-logging level gate (`0` = off, the default). The loader patches this to the operator's
/// chosen level so the datapath emits only records at or above it — keeping the `aya-log` calls
/// compiled in but never executed on the production hot path when off.
///
/// Encoding matches `log::LevelFilter` (see [`level`]): `Off=0, Error=1, Warn=2, Info=3, Debug=4,
/// Trace=5`. A macro at level L runs only when `log_level() >= L`.
#[allow(unsafe_code)]
#[export_name = "log_level"]
static LOG_LEVEL: u8 = 0;

/// Loader-patched verbose-logging level (see [`LOG_LEVEL`]). `0` = off; higher = more verbose,
/// using the `log::LevelFilter` encoding in [`level`].
#[allow(unsafe_code)]
#[inline(always)]
pub fn log_level() -> u8 {
    // SAFETY: read_volatile of a loader-patched read-only global; no aliasing, prevents caching.
    unsafe { core::ptr::read_volatile(&LOG_LEVEL) }
}

/// Numeric log levels, matching userspace `log::LevelFilter` so the loader can patch [`LOG_LEVEL`]
/// directly from it. A datapath macro at level L is emitted only when `log_level() >= L`.
///
/// The full set is kept for parity with `log::LevelFilter`; the datapath currently only compares
/// against `WARN` and `DEBUG`, so `ERROR`/`INFO`/`TRACE` are unused today (hence `dead_code`).
#[allow(dead_code)]
pub mod level {
    /// Enable `error!` and above.
    pub const ERROR: u8 = 1;
    /// Enable `warn!` and above.
    pub const WARN: u8 = 2;
    /// Enable `info!` and above.
    pub const INFO: u8 = 3;
    /// Enable `debug!` and above.
    pub const DEBUG: u8 = 4;
    /// Enable `trace!` and above.
    pub const TRACE: u8 = 5;
}
