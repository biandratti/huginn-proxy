//! Agent environment variable names. One definition so parse, errors, and tests stay in sync.

pub const INTERFACE: &str = "HUGINN_EBPF_INTERFACE";
pub const DST_IP_V4: &str = "HUGINN_EBPF_DST_IP_V4";
pub const DST_IP_V6: &str = "HUGINN_EBPF_DST_IP_V6";
pub const DST_PORTS: &str = "HUGINN_EBPF_DST_PORTS";
pub const PIN_PATH: &str = "HUGINN_EBPF_PIN_PATH";
pub const LINK_PIN_PATH: &str = "HUGINN_EBPF_LINK_PIN_PATH";
pub const SYN_MAP_MAX_ENTRIES: &str = "HUGINN_EBPF_SYN_MAP_MAX_ENTRIES";
pub const CAPTURE: &str = "HUGINN_EBPF_CAPTURE";
pub const METRICS_ADDR: &str = "HUGINN_EBPF_METRICS_ADDR";
pub const METRICS_PORT: &str = "HUGINN_EBPF_METRICS_PORT";
pub const LOG_LEVEL: &str = "HUGINN_EBPF_LOG_LEVEL";
pub const DRAIN_DELAY_SECS: &str = "HUGINN_EBPF_DRAIN_DELAY_SECS";
pub const HEARTBEAT_SECS: &str = "HUGINN_EBPF_HEARTBEAT_SECS";
pub const HEALTH_FORMAT: &str = "HUGINN_EBPF_HEALTH_FORMAT";
pub const RATE_LIMIT_ENABLED: &str = "HUGINN_EBPF_RATE_LIMIT_ENABLED";
pub const RATE_LIMIT_BURST: &str = "HUGINN_EBPF_RATE_LIMIT_BURST";
pub const RATE_LIMIT_WINDOW_SECONDS: &str = "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS";
