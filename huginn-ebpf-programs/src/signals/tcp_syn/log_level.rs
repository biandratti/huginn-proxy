//! Loader-patched `log_level` global (`log::LevelFilter` encoding).

#[allow(unsafe_code)]
#[export_name = "log_level"]
static LOG_LEVEL: u8 = 0;

#[allow(unsafe_code)]
#[inline(always)]
pub fn log_level() -> u8 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&LOG_LEVEL) }
}

#[allow(dead_code)]
pub mod level {
    pub const ERROR: u8 = 1;
    pub const WARN: u8 = 2;
    pub const INFO: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const TRACE: u8 = 5;
}
