//! Code shared by `std-binary` and `std-stack-binary`.
//!
//! `std-stack-binary` aborts on any heap allocation, so everything reachable
//! without the `std` and `alloc` features must stay off the heap.

#![allow(clippy::result_large_err)]

pub mod client;
pub mod io;
pub mod keys;
pub mod path;
pub mod time;
