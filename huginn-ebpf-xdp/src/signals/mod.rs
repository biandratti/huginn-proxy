//! Signal modules: each captures a specific observable (e.g. TCP SYN for OS fingerprinting).
//! The XDP pipeline dispatches to each signal's handler after parsing the packet.

pub mod tcp_syn;
