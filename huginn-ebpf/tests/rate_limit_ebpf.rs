//! Loads the real BPF program onto `lo` and drives it with real TCP connections to check the
//! rate limiter's promise: every SYN still passes (the connection completes), but once a source
//! goes over `burst`, its extra SYNs are not saved to the fingerprint map.
//!
//! With burst = 5 and 10 connections: all 10 handshakes complete (nothing dropped), but a direct
//! lookup in the real map (the same lookup the proxy does) finds only the first 5 keys; the
//! other 5 are missing.
//!
//! Covers IPv4 and IPv6, and both capture backends (generic XDP and TC) that `lo` can attach.
//!
//! Needs root (CAP_BPF / CAP_NET_ADMIN / CAP_PERFMON) and loopback XDP/TC support, which the CI
//! runner does not have, so these are `#[ignore]`d by default. Run them explicitly on a
//! privileged Linux host:
//!
//!   cargo test -p huginn-ebpf --test rate_limit_ebpf -- --ignored --nocapture

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use huginn_ebpf::{
    syn_captured_v4_count_from_path, syn_captured_v6_count_from_path,
    syn_rate_allowed_v4_count_from_path, syn_rate_allowed_v6_count_from_path,
    syn_rate_skipped_v4_count_from_path, syn_rate_skipped_v6_count_from_path, CaptureBackend,
    EbpfLogLevel, EbpfProbe, SynRateLimit, XdpAttachMode,
};

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

fn load_probe(
    port: u16,
    dst_v4: Ipv4Addr,
    dst_v6: Ipv6Addr,
    capture: CaptureBackend,
) -> (EbpfProbe, String) {
    assert!(pin_to_cpu0(), "sched_setaffinity failed");

    let pin_base = format!("/sys/fs/bpf/huginn-test-rate-limit-{}-{}", std::process::id(), port);

    // Window long enough that it never rotates during the test.
    let rate_limit = SynRateLimit::from_burst_window(true, BURST, 60);
    let probe = EbpfProbe::new(
        "lo",
        dst_v4,
        dst_v6,
        port,
        huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES,
        capture,
        EbpfLogLevel::Off,
        &pin_base,
        &huginn_ebpf::pin::capture_link_path(&pin_base),
        rate_limit,
    )
    .unwrap_or_else(|e| {
        panic!(
            "could not load/attach the BPF program ({e}). Needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON."
        )
    });
    (probe, pin_base)
}

/// Listen but never accept: the kernel finishes each handshake from the backlog, so every
/// connect succeeds. One SYN per connect hits `port`; the SYN-ACK goes to an ephemeral port
/// and is filtered out.
fn drive_connections(bind: IpAddr, port: u16) -> Vec<u16> {
    let _listener = TcpListener::bind(SocketAddr::new(bind, port))
        .unwrap_or_else(|e| panic!("bind listener on {bind}:{port}: {e}"));

    let mut client_ports = Vec::with_capacity(CONNECTIONS as usize);
    for _ in 0..CONNECTIONS {
        let stream =
            TcpStream::connect_timeout(&SocketAddr::new(bind, port), Duration::from_millis(500))
                .unwrap_or_else(|e| panic!("connection was dropped, not just un-captured: {e}"));
        let local = stream
            .local_addr()
            .unwrap_or_else(|e| panic!("local addr: {e}"));
        client_ports.push(local.port());
    }
    client_ports
}

fn assert_v4_burst(probe: &EbpfProbe, pin_base: &str, src: Ipv4Addr, client_ports: &[u16]) {
    for (i, &port) in client_ports.iter().enumerate() {
        let found = probe.lookup(src, port).is_some();
        if i < BURST as usize {
            assert!(found, "v4 connection {i} (port {port}) should be captured in the map");
        } else {
            assert!(
                !found,
                "v4 connection {i} (port {port}) is over burst, must not be in the map"
            );
        }
    }

    let allowed = syn_rate_allowed_v4_count_from_path(pin_base).unwrap_or(0);
    let skipped = syn_rate_skipped_v4_count_from_path(pin_base).unwrap_or(0);
    let captured = syn_captured_v4_count_from_path(pin_base).unwrap_or(0);
    assert_eq!(allowed, u64::from(BURST), "only `burst` v4 SYNs allowed to capture");
    assert_eq!(skipped, u64::from(CONNECTIONS - BURST), "v4 SYNs over `burst` skipped");
    assert_eq!(captured, u64::from(BURST), "v4 map written only for the allowed SYNs");
}

fn assert_v6_burst(probe: &EbpfProbe, pin_base: &str, src: Ipv6Addr, client_ports: &[u16]) {
    for (i, &port) in client_ports.iter().enumerate() {
        let found = probe.lookup_v6(src, port).is_some();
        if i < BURST as usize {
            assert!(found, "v6 connection {i} (port {port}) should be captured in the map");
        } else {
            assert!(
                !found,
                "v6 connection {i} (port {port}) is over burst, must not be in the map"
            );
        }
    }

    let allowed = syn_rate_allowed_v6_count_from_path(pin_base).unwrap_or(0);
    let skipped = syn_rate_skipped_v6_count_from_path(pin_base).unwrap_or(0);
    let captured = syn_captured_v6_count_from_path(pin_base).unwrap_or(0);
    assert_eq!(allowed, u64::from(BURST), "only `burst` v6 SYNs allowed to capture");
    assert_eq!(skipped, u64::from(CONNECTIONS - BURST), "v6 SYNs over `burst` skipped");
    assert_eq!(captured, u64::from(BURST), "v6 map written only for the allowed SYNs");
}

fn run_v4(port: u16, capture: CaptureBackend) {
    let (probe, pin_base) = load_probe(port, Ipv4Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED, capture);
    let ports = drive_connections(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    assert_v4_burst(&probe, &pin_base, Ipv4Addr::LOCALHOST, &ports);
    drop(probe);
    let _ = std::fs::remove_dir_all(&pin_base);
}

fn run_v6(port: u16, capture: CaptureBackend) {
    let (probe, pin_base) = load_probe(port, Ipv4Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, capture);
    let ports = drive_connections(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
    assert_v6_burst(&probe, &pin_base, Ipv6Addr::LOCALHOST, &ports);
    drop(probe);
    let _ = std::fs::remove_dir_all(&pin_base);
}

#[test]
#[ignore = "needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and generic XDP on loopback; not available on the normal CI runner"]
fn rate_limiter_v4_xdp_skb() {
    run_v4(58_432, CaptureBackend::Xdp(XdpAttachMode::Skb));
}

#[test]
#[ignore = "needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and generic XDP on loopback; not available on the normal CI runner"]
fn rate_limiter_v6_xdp_skb() {
    run_v6(58_433, CaptureBackend::Xdp(XdpAttachMode::Skb));
}

#[test]
#[ignore = "needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and TC clsact on loopback; not available on the normal CI runner"]
fn rate_limiter_v4_tc() {
    run_v4(58_434, CaptureBackend::Tc);
}

#[test]
#[ignore = "needs CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON and TC clsact on loopback; not available on the normal CI runner"]
fn rate_limiter_v6_tc() {
    run_v6(58_435, CaptureBackend::Tc);
}
