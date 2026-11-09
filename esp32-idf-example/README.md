# tftp-dus on an ESP32 with `std`

A TFTP server running on [ESP-IDF](https://github.com/espressif/esp-idf) over Wi-Fi, as an example of using the `tftp-dus` library with Rust `std` on a microcontroller. It serves `hello.txt` and stores uploads in flash.

- `src/net.rs`: the library's `Socket` and `BoundSocket` traits on top of `std::net`
- `src/storage.rs`: files through `std::fs`
- `src/lib.rs`: limits and the server
- `src/main.rs`: ESP specific setup, Wi-Fi and mounting the flash partition

Only `main.rs` depends on the chip. The rest also builds on a PC, where the tests run real transfers over loopback.

See [`esp32-example`](../esp32-example/README.md) for the same server without `std`. Compared to it, this one has a much simpler network layer and real file storage, but relies on ESP-IDF's heap and needs a heavier toolchain.

## Status

The default chip is the original ESP32. Its firmware has been run on a real board with ESP-IDF v5.3.3, where `./test-device` passes: a download and a 4 KB upload to flash over Wi-Fi, without encryption. The stack sizes below have only been tried with one client at a time. The ESP32-C3 firmware builds and links but has not been run. The host tests pass.

## Memory and limits

`tftp-dus` is built with `std`, `alloc` and `multi_thread`, so limits are normal values in `src/lib.rs` rather than `TFTP_*` build variables: 4 connections, window size 4, block size 1024 and 1 MB per file.

Each connection runs in its own thread with a 16 KB stack (`CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT` in `sdkconfig.defaults`), and its buffers are on the heap. Lower the stack size only after measuring it on a device.

Files are stored on a 1.4 MB SPIFFS partition, see `partitions.csv`. SPIFFS has no directories, so only plain file names of up to 32 bytes work, and uploads to `folder/file` are refused.

## Build and flash (ESP32)

The original ESP32 is Xtensa and needs Espressif's toolchain from [`espup`](https://github.com/esp-rs/espup):

```bash
cargo install espup ldproxy espflash
espup install
. ~/export-esp.sh

export WIFI_SSID=my-network
export WIFI_PASSWORD=my-password
cargo +esp run-device
```

Only WPA2 personal networks are configured. `rust-toolchain.toml` selects a pinned nightly with `rust-src` for host tests and ESP32-C3 builds, because Rust `std` for ESP-IDF is a tier 3 target and later nightlies have failed to compile it. `+esp` overrides it.

The first build downloads ESP-IDF and its tools, several GB, into `.embuild`, and takes a while. If `IDF_PATH` is set in your shell, that checkout is used instead, so unset it unless it is ESP-IDF 5.x.

### If the toolchain install fails with `libxml2.so.2`

ESP-IDF's `clang` needs `libxml2.so.2`, which newer distributions such as Arch no longer ship by default. Either install a compatibility package, or skip that `clang` by activating ESP-IDF yourself and using the system one:

```bash
git clone -b v5.3.3 --depth 1 --recursive --shallow-submodules \
    https://github.com/espressif/esp-idf ~/esp/esp-idf-v5.3.3
~/esp/esp-idf-v5.3.3/install.sh esp32
. ~/esp/esp-idf-v5.3.3/export.sh

export ESP_IDF_TOOLS_INSTALL_DIR=fromenv LIBCLANG_PATH=/usr/lib
cargo +esp run-device
```

## Try it

lwIP can not share a port between sockets, so the device answers each client from a new port and the client must allow that:

```bash
tftp-dus receive 192.168.1.50:69 hello.txt --local-path hello.txt --allow-server-port-change
tftp-dus send 192.168.1.50:69 notes.txt --allow-server-port-change
```

Standard TFTP clients work this way by default. Encryption is not enabled in this example.

## ESP32-C3

The chip is selected by `MCU` and the target. The ESP32-C3 is RISC-V and uses the nightly from `rust-toolchain.toml`:

```bash
MCU=esp32c3 cargo run --release --target riscv32imc-esp-espidf
```

`./test-device` only supports the original ESP32.

## Test on a device

With a board connected, this builds and flashes the firmware, downloads `hello.txt`, uploads a file, downloads it again to compare, and exits with the result:

```bash
export WIFI_SSID=my-network
export WIFI_PASSWORD=my-password
./test-device
```

Your computer must be on the same network as the device. Set `ESPFLASH_PORT` if more than one serial port is connected. Linux only.

## Tests

```bash
cargo test-host
```
