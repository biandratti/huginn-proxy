#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

/// Returns a const pointer to `T` at `offset` bytes from the start of the
/// packet, or `None` if the access would exceed `data_end`.
///
/// The BPF verifier accepts this pattern (explicit bounds check before cast).
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let access_end = start
        .checked_add(offset)?
        .checked_add(mem::size_of::<T>())?;
    if access_end > end {
        return None;
    }
    Some(start.checked_add(offset)? as *const T)
}
