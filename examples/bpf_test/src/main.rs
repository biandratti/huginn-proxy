//! Dev-only: load the XDP ELF and check that expected maps.
//!
//! Use when verifying BPF works on your machine (e.g. after kernel/capability changes).
//!
//! Run:
//!   cargo run -p bpf-test
//!
//! If you get PermissionDenied (map creation needs CAP_BPF), build as user and run the binary with sudo:
//!   cargo build -p bpf-test  &&  sudo ./target/debug/bpf-test

fn main() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tracing::info!("Loading XDP ELF and checking maps...");

    let bytes = huginn_ebpf::bpf_object_bytes();

    match aya::Ebpf::load(bytes) {
        Ok(ebpf) => {
            let expected = [
                huginn_ebpf::pin::SYN_MAP_V4_NAME,
                huginn_ebpf::pin::COUNTER_NAME,
                huginn_ebpf::pin::SYN_INSERT_FAILURES_V4_NAME,
            ];
            for name in expected {
                if ebpf.map(name).is_some() {
                    tracing::info!("  map '{name}' OK");
                } else {
                    tracing::error!("  map '{name}' MISSING");
                    std::process::exit(1);
                }
            }
            tracing::info!("SUCCESS: ELF loaded and all expected maps present");
        }
        Err(e) => {
            tracing::error!(error = ?e, "FAILED: BPF ELF load error");
            let msg = e.to_string();
            if msg.contains("PermissionDenied") || msg.contains("Operation not permitted") {
                tracing::warn!("Map creation needs CAP_BPF. Build then run the binary with sudo:");
                tracing::warn!("  cargo build -p bpf-test  &&  sudo ./target/debug/bpf-test");
            }
            tracing::warn!("Check: sudo cat /proc/sys/kernel/unprivileged_bpf_disabled");
            tracing::warn!("Check: sudo dmesg | grep -i bpf | tail -5");
            std::process::exit(1);
        }
    }
}
