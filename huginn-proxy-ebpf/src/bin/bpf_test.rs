/// Minimal diagnostic: tries to load the BPF ELF and create maps.
///
/// Log level resolution (mirrors init_tracing_with_otel, first wins):
///   1. RUST_LOG env:  RUST_LOG=debug sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test
///   2. CLI argument:  sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test -- debug
///   3. Default:       info
fn main() {
    let default_level = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tracing::info!("Testing BPF map creation with aya...");

    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp.bpf.o"));

    match aya::Ebpf::load(bytes) {
        Ok(_ebpf) => {
            tracing::info!("SUCCESS: BPF ELF loaded and all maps created OK");
            tracing::info!("BPF works on this system. Problem is Docker-specific.");
        }
        Err(e) => {
            tracing::error!(error = ?e, "FAILED: BPF ELF load error");
            tracing::warn!("Check: sudo cat /proc/sys/kernel/unprivileged_bpf_disabled");
            tracing::warn!("Check: sudo dmesg | grep -i bpf | tail -5");
        }
    }
}
