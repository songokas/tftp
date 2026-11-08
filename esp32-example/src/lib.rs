//! Board independent part of the example: `tftp-dus` over `smoltcp` and a RAM
//! file store. It builds for the host too, so transfers can be tested there.

#![no_std]
#![allow(clippy::result_large_err)]

pub mod net;
pub mod storage;
