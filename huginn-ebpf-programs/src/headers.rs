// Header structs now live in huginn-ebpf-common so they can be tested on host.
// Re-export everything so all call sites in this crate remain unchanged.
pub use huginn_ebpf_common::headers::{EthHdr, Ip4Hdr, Ip6Hdr, TcpHdr, VlanHdr};
