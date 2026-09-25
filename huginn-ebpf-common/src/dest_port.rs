/// Whether a TCP destination port is in the capture list.
///
/// `dest`, `first`, and `second` use the same encoding as `TcpHdr.dest` (network byte
/// order as read on a little-endian CPU). The loader patches the BPF globals with
/// `u16::to_be()`.
///
/// `first` is the required port. `second == 0` means the list has one port. A zero
/// `first` does not disable the filter.
#[inline(always)]
#[must_use]
pub fn dest_port_allowed(dest: u16, first: u16, second: u16) -> bool {
    dest == first || (second != 0 && dest == second)
}
