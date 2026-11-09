//! Global allocator that turns any heap allocation into an immediate abort,
//! so "stack only" is enforced at runtime rather than assumed.

use core::alloc::GlobalAlloc;
use core::alloc::Layout;

pub struct DenyHeap;

const MESSAGE: &str =
    "tftp-dus-stack-only: heap allocation attempted (or a panic message was formatted), aborting\n";

unsafe impl GlobalAlloc for DenyHeap {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        libc::write(2, MESSAGE.as_ptr().cast(), MESSAGE.len());
        libc::abort()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
