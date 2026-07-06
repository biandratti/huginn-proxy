//! Bounds-checked packet pointer access for XDP.

use aya_ebpf::programs::XdpContext;
use core::mem;

/// # Safety
///
/// Caller may only dereference when `Some` is returned.
#[allow(unsafe_code)]
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
