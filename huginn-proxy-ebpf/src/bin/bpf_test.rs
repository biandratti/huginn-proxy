/// Minimal diagnostic: tries to load the BPF ELF and create maps.
/// Run with: sudo -E cargo run -p huginn-proxy-ebpf --bin bpf_test
fn main() {
    println!("Testing BPF map creation with aya...");

    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp.bpf.o"));

    match aya::Ebpf::load(bytes) {
        Ok(_ebpf) => {
            println!("SUCCESS: BPF ELF loaded and all maps created OK");
            println!("BPF works on this system. Problem is Docker-specific.");
        }
        Err(e) => {
            println!("FAILED: {e:#?}");
            println!();
            println!("Check: sudo cat /proc/sys/kernel/unprivileged_bpf_disabled");
            println!("Check: sudo dmesg | grep -i bpf | tail -5");
        }
    }
}
