# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Linux CI runs `cargo fmt --check`, `cargo clippy` and `./test test_all`. `rustfmt.toml` uses unstable options (one import per line, grouped std/external/crate), which stable rustfmt ignores with a warning, so keep that import style by hand.

```bash
cargo test                                       # library only (root package)
cargo test -p tftp-dus <test_name>               # one library test
cargo test -p tftp-std-binary <test_name>        # one std-binary test
cargo test -p tftp-dus --no-default-features --features encryption   # one feature combination

# standalone crates are not workspace members
cargo test --manifest-path std-stack-binary/Cargo.toml <test_name>
(cd esp32-example && cargo test-host)            # alias in its .cargo/config.toml; run from inside the crate
(cd esp32-idf-example && cargo test-host)        # same; needs its pinned nightly with rust-src

./test test_lib                                  # library across feature combinations
./test test_bin                                  # std-binary across feature combinations
./test test_stack_bin                            # std-stack-binary, including custom TFTP_* limits
./test test_all                                  # everything; slow, transfers files over 100 MB

# run one end-to-end scenario: build the binaries once, then pass server, client and arguments
./test build_release_targets
./test test_large_files ./target/tftp ./target/tftp-stack-encryption 4
```

- End-to-end scenarios use fixed ports (mostly 9000) and a shared `target/tftp-232342` directory, so they cannot run concurrently.
- `build_release_targets` produces `target/tftp` (default features), `tftp-alloc`, `tftp-stack`, `tftp-stack-encryption` and `tftp-stack-only`.
- `cargo fmt` and `cargo clippy` at the root do not cover the three standalone crates; use `--manifest-path` or run them from the crate.
- `benches/` needs nightly (`#![feature(test)]`).
- `./build build_stack` builds the stack only binary into `dist/`. `./build release_dist` deletes `dist/*` first.
- Run `cross` for `std-stack-binary` from inside that directory; from the root it fails with a duplicate mount point.

## Repository layout

| Crate | Path | Role |
|---|---|---|
| `tftp-dus` | `.` | protocol library, `no_std` capable |
| `tftp-std-binary` | `std-binary` | main `tftp-dus` CLI |
| `tftp-binary-common` | `binary-common` | code shared by the two std binaries |
| `tftp-std-stack-binary` | `std-stack-binary` | `tftp-dus-stack-only`, Linux and macOS, no heap |
| `tftp-esp32-example` | `esp32-example` | `no_std` ESP32-C3 Wi-Fi server example |
| `tftp-esp32-idf-example` | `esp32-idf-example` | ESP-IDF `std` server example with files in flash |

`std-stack-binary`, `esp32-example` and `esp32-idf-example` are listed under `exclude` in the root `Cargo.toml` and have their own `[workspace]` and `Cargo.lock`. This is deliberate: as workspace members, Cargo feature unification would turn `alloc` or `std` back on in the library for them.

## Library architecture

The library has no I/O of its own. Binaries inject everything through generics: `server()` (`src/server/`) and `send_file`/`receive_file` (`src/client/`) take closures that create readers, writers and sockets, plus an `InstantCallback` for time. A new platform implements `Socket` and `BoundSocket` (`src/socket.rs`) and the `Read`/`Write`/`Seek` traits from `std_compat::io`; `esp32-example/src/net.rs` is a minimal example.

### Features change the code that is compiled

Most behaviour differences come from features, so check a change against more than the default set:

- **`alloc`** switches the aliases in `lib.rs` (`types::DataBuffer`, `FilePath`, `DefaultString`, ...) and `map::Map` between `Vec`/`String`/`BTreeMap` and `heapless` equivalents. Use these aliases rather than concrete types. Limits differ too, in the `cfg_alloc!`/`cfg_stack!` blocks of `src/config.rs`.
- **`std`** selects `std_compat`: re-exports of `std` (inline in `lib.rs`) or hand written `no_std` versions (`src/std_compat.rs`). Library code uses `crate::std_compat` and `core::`; `std::` is only for code gated on the `std` feature or tests.
- **`multi_thread`** selects `server/multi_thread.rs` (one thread per connection) or `server/single_thread.rs` (one poll loop with fixed reader pools). `Socket` gains `notified` and `add_interest` only in the single threaded build.
- **`encryption`** and **`metrics`**, when off, are replaced by stubs in `lib.rs` with the same names so call sites need no `cfg`. A new public item in `encryption`, `key_management` or `metrics` may need a matching stub.
- **`seek`** adds a `Seek` bound on readers and enables the seek reader pool.

Prefer the `cfg_alloc!`, `cfg_stack!`, `cfg_encryption!` and `cfg_seek!` macros in `src/macros.rs` for feature gated items.

### Build time limits

Without `alloc`, `src/config.rs` reads `TFTP_MAX_CLIENTS`, `TFTP_MAX_WINDOW_SIZE`, `TFTP_DEFAULT_WINDOW_SIZE`, `TFTP_MAX_BLOCK_SIZE` and `TFTP_MAX_{SINGLE,MULTI,SEEK}_READERS` with `option_env!`, and enforces them with compile time assertions. Map and pool capacities must be powers of two because `FnvIndexMap` requires it. `esp32-example/.cargo/config.toml` sets these through `[env]`. The table of constraints is in `README.md`; keep it in sync.

## Stack only binary invariants

`std-stack-binary` installs a global allocator (`deny_heap.rs`) that aborts on any Rust allocation, so a new allocation is a runtime crash, not a performance issue. Common sources in `std`:

- `std::env::args` (hence `#![no_main]` with a C `main`)
- `Display` for `io::Error` and `std::io::stdout`
- the stderr lock on macOS (hence direct `libc::write` in `stderr.rs`)
- `File::open` with paths of 384 bytes or more (hence `realpath` into a stack buffer and `libc::open`)
- `std::thread::spawn`

The poller is chosen per OS in `main.rs` (`poller_epoll.rs` or `poller_kqueue.rs`). Linux allocations can be checked with Valgrind DHAT, which also counts libc `malloc`.

## ESP32 example

`src/net.rs` and `src/storage.rs` compile on the host; `src/main.rs` is device only (feature `device`). Host tests run real transfers between two `smoltcp` stacks. The firmware needs `WIFI_SSID` and `WIFI_PASSWORD` at build time and uses `require_server_port_change: true`, because `smoltcp` sockets cannot share a port. TFTP is heap free, but `esp-radio` requires an allocator, so the firmware has a heap for the Wi-Fi driver only.

`esp32-idf-example` builds the library with `std`, `alloc` and `multi_thread`, so its limits are runtime values in `src/lib.rs`, not `TFTP_*` variables. It has the same split: `src/net.rs` and `src/storage.rs` also run on the host, over loopback. SPIFFS is flat, so `storage.rs` accepts only plain file names. The nightly in `rust-toolchain.toml` is pinned because newer `std` has not always compiled for ESP-IDF. A set `IDF_PATH` overrides `ESP_IDF_VERSION` and selects that ESP-IDF checkout instead.
