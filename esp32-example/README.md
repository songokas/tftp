# tftp-dus on an ESP32

A TFTP server running without `std` over Wi-Fi, as an example of using the `tftp-dus` library on a microcontroller. It serves `hello.txt` and stores uploads in RAM.

- `src/net.rs`: the library's `Socket` and `BoundSocket` traits on top of `smoltcp`
- `src/storage.rs`: a RAM file store, the part to replace with flash on a real device
- `src/main.rs`: ESP specific setup, Wi-Fi and the server

Only `main.rs` depends on the chip. The rest also builds on a PC, where the tests run real transfers between two `smoltcp` stacks.

## Status

The ESP32-C3 firmware builds and links, and the host tests pass, but this has **not been run on hardware yet**. The original ESP32 build has not been compiled either, because it needs Espressif's toolchain. `esp-radio` is still in beta and this example calls its hidden `receive` and `transmit` functions, so expect to adjust it when upgrading.

## Memory

TFTP itself does not use the heap: `tftp-dus` is built without `alloc`, and its buffers live in statics or on the stack. The Wi-Fi driver is the exception, because `esp-radio` requires an allocator, so a 72 KB heap is reserved for it.

| Reserved in RAM | Size |
|---|---|
| Wi-Fi driver heap | 72 KB |
| Socket buffers | 52 KB |
| File store (4 files of 8 KB) | 33 KB |

Limits are set by the `TFTP_*` variables in `.cargo/config.toml`: 4 clients, window size 4 and block size 1024. Socket buffers grow with all three.

## Build and flash (ESP32-C3)

```bash
rustup target add riscv32imc-unknown-none-elf
cargo install espflash

export WIFI_SSID=my-network
export WIFI_PASSWORD=my-password
cargo run --release
```

Only WPA2 personal networks are configured. The device prints its address once DHCP completes.

## Try it

The device has to answer from a new port for every client, because `smoltcp` can not share a port between sockets, so the client must allow that:

```bash
tftp-dus receive 192.168.1.50:69 hello.txt --local-path hello.txt --allow-server-port-change
tftp-dus send 192.168.1.50:69 notes.txt --allow-server-port-change
```

Standard TFTP clients work this way by default. Encryption is not enabled in this example.

## Original ESP32

The code selects the chip with a feature, but the original ESP32 is Xtensa and needs Espressif's toolchain from [`espup`](https://github.com/esp-rs/espup):

```bash
cargo +esp run --release --no-default-features --features esp32 \
    --target xtensa-esp32-none-elf -Zbuild-std=core,alloc
```

## Tests

```bash
cargo test-host
```
