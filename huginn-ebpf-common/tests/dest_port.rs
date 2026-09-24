//! Destination-port capture list shared by the BPF datapath and userspace tests.

use huginn_ebpf_common::dest_port_allowed;

const HTTP: u16 = 80;
const HTTPS: u16 = 443;
const OTHER: u16 = 22;

#[test]
fn one_port_accepts_only_that_port() {
    assert!(dest_port_allowed(HTTPS, HTTPS, 0));
    assert!(!dest_port_allowed(HTTP, HTTPS, 0));
    assert!(!dest_port_allowed(OTHER, HTTPS, 0));
}

#[test]
fn two_ports_accept_both_and_reject_a_third() {
    assert!(dest_port_allowed(HTTPS, HTTPS, HTTP));
    assert!(dest_port_allowed(HTTP, HTTPS, HTTP));
    assert!(!dest_port_allowed(OTHER, HTTPS, HTTP));
}

#[test]
fn a_zero_first_port_does_not_capture_every_syn() {
    assert!(!dest_port_allowed(HTTPS, 0, 0));
    assert!(!dest_port_allowed(HTTP, 0, 0));
    assert!(!dest_port_allowed(OTHER, 0, HTTPS));
}
