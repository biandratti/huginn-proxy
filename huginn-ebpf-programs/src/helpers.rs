#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

/// Returns a const pointer to `T` at `offset` bytes from the start of the
/// packet, or `None` if the access would exceed `data_end`.
///
/// # Safety
///
/// The caller may only dereference the returned pointer if `Some` was returned.
/// Bounds are checked against `ctx.data_end()` before the cast; the verifier
/// accepts this pattern.
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
