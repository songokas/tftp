//! TFTP client and server that performs no heap allocation.
//!
//! The Rust runtime's `main` is bypassed because `std::env::args` allocates.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(any(test, not(feature = "encryption")), allow(dead_code))]
#![allow(clippy::result_large_err)]

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("tftp-std-stack-binary only supports Linux and macOS");

mod cli;
mod client;
mod deny_heap;
mod error;
mod files;
mod logger;
#[cfg_attr(target_os = "linux", path = "poller_epoll.rs")]
#[cfg_attr(target_os = "macos", path = "poller_kqueue.rs")]
mod poller;
mod server;
mod socket;
mod stderr;

use core::ffi::c_int;
use core::fmt::Write;

use cli::Args;
use cli::Command;
use error::BinResult;
use stderr::write_all;
use stderr::Stderr;

#[cfg(not(test))]
#[global_allocator]
static HEAP: deny_heap::DenyHeap = deny_heap::DenyHeap;

const EXIT_SUCCESS: c_int = 0;
const EXIT_FAILURE: c_int = 1;
const EXIT_USAGE: c_int = 2;

fn execute(command: &Command<'_>) -> BinResult<()> {
    match command {
        Command::Send {
            config,
            local_path,
            remote_path,
            prefer_seek,
        } => client::start_send(config, local_path, *remote_path, *prefer_seek).map(|_| ()),
        Command::Receive {
            config,
            local_path,
            remote_path,
        } => client::start_receive(config, *local_path, remote_path).map(|_| ()),
        Command::Server(config) => server::start_server(config),
        Command::Help | Command::Version => Ok(()),
    }
}

fn run<'a>(arguments: impl Iterator<Item = &'a str>) -> c_int {
    let Args { verbosity, command } = match cli::parse(arguments) {
        Ok(args) => args,
        Err(e) => {
            let _ = writeln!(Stderr, "error: {e}\n\n{}", cli::USAGE);
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            write_all(1, cli::USAGE);
            return EXIT_SUCCESS;
        }
        Command::Version => {
            write_all(
                1,
                concat!("tftp-dus-stack-only ", env!("CARGO_PKG_VERSION"), "\n"),
            );
            return EXIT_SUCCESS;
        }
        _ => logger::init(verbosity),
    }
    match execute(&command) {
        Ok(()) => EXIT_SUCCESS,
        Err(e) => {
            log::error!("{e}");
            EXIT_FAILURE
        }
    }
}

/// # Safety
/// Called by the C runtime with a valid argv of argc NUL terminated strings.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn main(argc: c_int, argv: *const *const core::ffi::c_char) -> c_int {
    use core::ffi::CStr;

    let raw_arguments = (1..argc as usize).map(|index| CStr::from_ptr(*argv.add(index)));
    if raw_arguments.clone().any(|a| a.to_str().is_err()) {
        let _ = writeln!(Stderr, "error: arguments must be valid UTF-8");
        return EXIT_USAGE;
    }
    run(raw_arguments.map(|argument| argument.to_str().unwrap_or_default()))
}
