//! Loads the real BPF program onto `lo` and drives it with real TCP connections to check the
//! rate limiter's promise: every SYN still passes (the connection completes), but once a source
//! goes over `burst`, its extra SYNs are not saved to the fingerprint map.
//!
//! With burst = 5 and 10 connections: all 10 handshakes complete (nothing dropped), but a direct
//! lookup in the real map (the same lookup the proxy does) finds only the first 5 keys; the
//! other 5 are missing.
//!
//! Needs root (CAP_BPF / CAP_NET_ADMIN / CAP_PERFMON) and generic-XDP-on-loopback support, which
//! the CI runner does not have, so this is `#[ignore]`d by default. Run it explicitly on a
//! privileged Linux host:
//!
//!   cargo test -p huginn-ebpf --test rate_limit_ebpf -- --ignored --nocapture

use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::time::Duration;

use huginn_ebpf::{
    syn_captured_v4_count_from_path, syn_rate_allowed_v4_count_from_path,
    syn_rate_skipped_v4_count_from_path, CaptureBackend, EbpfLogLevel, EbpfProbe, SynRateLimit,
    XdpAttachMode,
};

const TEST_PORT: u16 = 58_432;
const BURST: u32 = 5;
const CONNECTIONS: u32 = 10;

/// Pin to one CPU. The sketch is per-CPU, so keeping every SYN on the same CPU makes the counts
/// deterministic instead of split across cores.
fn pin_to_cpu0() -> bool {
    // SAFETY: libc affinity call on a zeroed, correctly sized set.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(0, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

#[test]
#[ignore = "needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and generic XDP on loopback; not available on the normal CI runner"]
fn rate_limiter_passes_all_syns_but_captures_only_burst() {
    assert!(pin_to_cpu0(), "sched_setaffinity failed");

    let pin_base = format!("/sys/fs/bpf/huginn-test-rate-limit-{}", std::process::id());

    // Window long enough that it never rotates during the test
    let rate_limit = SynRateLimit::from_burst_window(true, BURST, 60);
    let probe = EbpfProbe::new(
        "lo",
        Ipv4Addr::LOCALHOST,
        Ipv6Addr::UNSPECIFIED,
        TEST_PORT,
        huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES,
        CaptureBackend::Xdp(XdpAttachMode::Skb),
        EbpfLogLevel::Off,
        &pin_base,
        rate_limit,
    );
    let probe = probe.unwrap_or_else(|e| {
        panic!(
            "could not load/attach the BPF program ({e}). Needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON."
        )
    });

    // Listen but never accept: the kernel finishes each handshake from the backlog, so every
    // connect succeeds. One SYN per connect hits TEST_PORT; the SYN-ACK goes to an ephemeral port
    // and is filtered out.
    let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, TEST_PORT))
        .unwrap_or_else(|e| panic!("bind listener: {e}"));

    // Every connect must succeed (over-limit SYNs are skipped, never dropped). The client's local
    // port is its map key, so record it for the lookup below.
    let mut client_ports = Vec::with_capacity(CONNECTIONS as usize);
    for _ in 0..CONNECTIONS {
        let stream = TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, TEST_PORT).into(),
            Duration::from_millis(500),
        )
        .unwrap_or_else(|e| panic!("connection was dropped, not just un-captured: {e}"));
        let port = stream
            .local_addr()
            .unwrap_or_else(|e| panic!("local addr: {e}"))
            .port();
        client_ports.push(port);
    }

    // Direct map check (the same lookup the proxy does): first `burst` keys present, rest missing.
    for (i, &port) in client_ports.iter().enumerate() {
        let found = probe.lookup(Ipv4Addr::LOCALHOST, port).is_some();
        if i < BURST as usize {
            assert!(found, "connection {i} (port {port}) should be captured in the map");
        } else {
            assert!(!found, "connection {i} (port {port}) is over burst, must not be in the map");
        }
    }

    let allowed = syn_rate_allowed_v4_count_from_path(&pin_base).unwrap_or(0);
    let skipped = syn_rate_skipped_v4_count_from_path(&pin_base).unwrap_or(0);
    let captured = syn_captured_v4_count_from_path(&pin_base).unwrap_or(0);

    drop(probe);
    let _ = std::fs::remove_dir_all(&pin_base);

    // Counters agree with the map lookups above.
    assert_eq!(allowed, u64::from(BURST), "only `burst` SYNs allowed to capture");
    assert_eq!(skipped, u64::from(CONNECTIONS - BURST), "SYNs over `burst` skipped");
    assert_eq!(captured, u64::from(BURST), "map written only for the allowed SYNs");
}
