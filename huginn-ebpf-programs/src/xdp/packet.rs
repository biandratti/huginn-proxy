//! Raw packet access for the XDP pipeline.
//!
//! XDP hands the program a pointer window (`ctx.data()`..`ctx.data_end()`); reading a header means
//! bounds-checking an offset and casting. This is intrinsically `unsafe` and verifier-mandated, so
//! it is confined to this module — the single `unsafe fn` below carries its own `#[allow]`.

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
