# tftp-dus on an ESP32

A TFTP server running without `std` over Wi-Fi, as an example of using the `tftp-dus` library on a microcontroller. It serves `hello.txt` and stores uploads in RAM.

- `src/net.rs`: the library's `Socket` and `BoundSocket` traits on top of `smoltcp`
- `src/storage.rs`: a RAM file store, the part to replace with flash on a real device
- `src/main.rs`: ESP specific setup, Wi-Fi and the server

Only `main.rs` depends on the chip. The rest also builds on a PC, where the tests run real transfers between two `smoltcp` stacks.

## Status

The default chip is the original ESP32. Its firmware has been run on a real board, where `./test-device` passes: a download and a 4 KB upload over Wi-Fi, without encryption. The ESP32-C3 firmware builds and links but has not been run. The host tests pass. `esp-radio` is still in beta and this example calls its hidden `receive` and `transmit` functions, so expect to adjust it when upgrading.

## Memory

TFTP itself does not use the heap: `tftp-dus` is built without `alloc`, and its buffers live in statics or on the stack. The Wi-Fi driver is the exception, because `esp-radio` requires an allocator, so a 72 KB heap is reserved for it.

| Reserved in RAM | Size |
|---|---|
| Wi-Fi driver heap | 72 KB |
| Socket buffers | 52 KB |
| File store (4 files of 8 KB) | 33 KB |

On the original ESP32 the heap is in its second RAM region, because the stack gets whatever the statics leave of the first one: about 80 KB. The server needs more than 33 KB of stack, since the library's reader pools live there.

Limits are set by the `TFTP_*` variables in `.cargo/config.toml`: 4 clients, window size 4 and block size 1024. Socket buffers grow with all three.

## Build and flash (ESP32)

The original ESP32 is Xtensa and needs Espressif's toolchain from [`espup`](https://github.com/esp-rs/espup):

```bash
cargo install espup espflash
espup install
. ~/export-esp.sh

export WIFI_SSID=my-network
export WIFI_PASSWORD=my-password
cargo +esp run-device
```

Only WPA2 personal networks are configured. The device prints its address once DHCP completes.

## Try it

The device has to answer from a new port for every client, because `smoltcp` can not share a port between sockets, so the client must allow that:

```bash
tftp-dus receive 192.168.1.50:69 hello.txt --local-path hello.txt --allow-server-port-change
tftp-dus send 192.168.1.50:69 notes.txt --allow-server-port-change
```

Standard TFTP clients work this way by default. Encryption is not enabled in this example.

## ESP32-C3

The code selects the chip with a feature. The ESP32-C3 is RISC-V and works with the standard toolchain:

```bash
rustup target add riscv32imc-unknown-none-elf
cargo run --release --no-default-features --features esp32c3 \
    --target riscv32imc-unknown-none-elf
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
