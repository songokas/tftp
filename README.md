# tftp

Simple tftp protocol client and server implementation in rust.

Adheres to RFCs:

- [rfc1350](https://www.rfc-editor.org/rfc/rfc1350)
- [rfc2347](https://www.rfc-editor.org/rfc/rfc2347)
- [rfc2348](https://www.rfc-editor.org/rfc/rfc2348)
- [rfc2349](https://www.rfc-editor.org/rfc/rfc2349)
- [rfc7440](https://www.rfc-editor.org/rfc/rfc7440)

Additionally public/private keys and xchacha20poly1305 encryption can be used to
encrypt traffic or data.

## Installing

Install deb

```
wget https://github.com/songokas/tftp/releases/download/v0.7.3/tftp-dus_0.7.3_amd64.deb \
  && sudo apt install ./tftp-dus_0.7.3_amd64.deb
```

Download binary

https://github.com/songokas/tftp/releases

Install from source

```bash
cargo install --root=$HOME/.local --git=https://github.com/songokas/tftp
```

## Getting started

Run the server and send a file

```bash
tftp-dus server 127.0.0.1:9000 /tmp
echo "hello" | tftp-dus send 127.0.0.1:9000 /dev/stdin
```

## Features

- low memory consumption
- supports tsize, blksize, timeout, windowsize options
- send/receive encrypted files
- authorization of public keys
- optional stack only functionality (library and the Linux and macOS `std-stack-binary`)
  - `multi_thread` without `alloc` keeps buffers on the stack, but `std::thread::spawn` still heap allocates per connection
- compatible with third party clients,servers
- large file support
- ability to synchronize new files in a folder

## Building `tftp-dus` without `alloc`

`alloc` is enabled by default. Without it, transfers use fixed size stack buffers, so memory use does not grow with file size and limits are set at build time:

```bash
cargo build --release -p tftp-std-binary --no-default-features --features encryption,seek
```

| Limit | With `alloc` | Without `alloc` |
|---|---|---|
| Clients | 5000 | 128 |
| Window size (default) | 1000 (8) | 16 (4) |
| Block size | 65464 | 1425 |
| Default string, e.g. error message | unbounded | 140 bytes |
| File path | unbounded | 150 bytes |

- Without `multi_thread`, the server is single threaded and keeps downloads in fixed pools: 64 with window size 1, 8 with a larger window and, with `seek`, 64 seek readers used when the others run out. Downloads that do not fit are refused with a `Server resources busy` error.
- With `multi_thread`, each connection has its own thread and there are no reader pools.
- `sync` requires `alloc`, so enabling it turns `alloc` back on.
- The binary is not heap free: argument parsing, logging, socket polling, path resolution, directory listing and `std::thread::spawn` still allocate. This is a small amount per process or connection and does not depend on file size. Use `std-stack-binary` if nothing may allocate.

## Stack only binary

`std-stack-binary` builds `tftp-dus-stack-only`, a single threaded Linux and macOS client and server that aborts if anything allocates through the Rust allocator.

```bash
cargo build --release --manifest-path std-stack-binary/Cargo.toml
```

Compared to `tftp-dus`, addresses must be IP literals, there is no `sync`, `--directory-list` or metrics, and limits are fixed at build time.

### Changing stack limits

Limits of builds without `alloc` come from environment variables read at compile time, so no code changes are needed. Unset variables keep their defaults, and an invalid value fails the build.

```bash
TFTP_MAX_CLIENTS=512 TFTP_MAX_WINDOW_SIZE=32 ./build build_stack
```

| Variable | Default | Constraint |
|---|---|---|
| `TFTP_MAX_CLIENTS` | 128 | power of two, at least 2 |
| `TFTP_MAX_WINDOW_SIZE` | 16 | at least 1 |
| `TFTP_DEFAULT_WINDOW_SIZE` | 4 | at most 255 and `TFTP_MAX_WINDOW_SIZE` |
| `TFTP_MAX_BLOCK_SIZE` | 1425 | 8 to 65464 |
| `TFTP_MAX_SINGLE_READERS` | `TFTP_MAX_CLIENTS / 2` | power of two, at least 2 |
| `TFTP_MAX_MULTI_READERS` | `TFTP_MAX_CLIENTS / 16` | power of two, at least 2 |
| `TFTP_MAX_SEEK_READERS` | `TFTP_MAX_CLIENTS / 2` | power of two, at least 2 |

The same variables apply to `std-binary` built without `alloc`.

Larger limits need more stack, reserved when the server starts. If it crashes on startup, raise the limit with `ulimit -s` (or `LimitSTACK=` in a systemd unit). More than about 500 clients also needs a higher `ulimit -n`. On macOS the default open file limit is usually 256, so raise it for more than about 120 clients.

## Embedded example

`esp32-example` runs the `tftp-dus` server without `std` on an ESP32-C3 over Wi-Fi, see [its README](esp32-example/README.md).

`esp32-idf-example` runs it with `std` on ESP-IDF and stores files in flash, see [its README](esp32-idf-example/README.md).

## TFTP Extensions

### Standard extensions

| Extension | RFC | Wire name | Range | Description |
|---|---|---|---|---|
| Block size | [rfc2348](https://www.rfc-editor.org/rfc/rfc2348) | `blksize` | 8–65464 | Negotiated payload size per DATA packet. Larger blocks reduce overhead on fast links. |
| Timeout | [rfc2349](https://www.rfc-editor.org/rfc/rfc2349) | `timeout` | 1–255 s | Retransmit timeout in seconds. Overrides the built-in default. |
| Transfer size | [rfc2349](https://www.rfc-editor.org/rfc/rfc2349) | `tsize` | 0–2⁶⁴ | File size in bytes. Sent by the client on write; echoed by the server on read so the receiver can pre-allocate. |
| Window size | [rfc7440](https://www.rfc-editor.org/rfc/rfc7440) | `windowsize` | 1–65535 | Number of DATA blocks in flight before an ACK is required. Increases throughput on high-latency links. |

### Custom extensions (encryption, feature-gated)

These extensions are negotiated in the initial RRQ/WRQ and OACK exchange. They are only sent when the `encryption` feature is compiled in.

| Extension | Wire name | Value | Description |
|---|---|---|---|
| Encryption level | `enclevel` | `none` / `data` / `protocol` / `full` / `optional-protocol` / `optional-full` | Requested encryption scope. `data` encrypts only file content; `protocol` encrypts all TFTP packets; `full` combines both. The `optional-*` variants allow falling back to plaintext if the peer does not support encryption. |
| Session public key | `spubk` | base64 x25519 key | Ephemeral x25519 public key for Diffie–Hellman key exchange. Both sides contribute one; the shared secret seeds the xchacha20poly1305 stream cipher. |
| Auth public key | `apubk` | base64 ed25519 key | Long-term ed25519 public key of the sender, used to verify the `sig` extension. |
| Signature | `sig` | base64 ed25519 signature | ed25519 signature over the request, proving possession of the private key that corresponds to `apubk`. The server checks this against its `--authorized-keys` list. |

### Configuration

Run help to see all available options

```bash
tftp-dus server --help
tftp-dus send --help
tftp-dus receive --help
tftp-dus sync --help
```

#### Using encryption with server

As long as the binary is compiled with feature=encryption optional encryption will be enabled automatically

server will generate a random key per client if no private key is provided

```bash
tftp-dus server 127.0.0.1:9000 /tmp
```

restrict who is able to access the server (server public key will be printed in the logs)

```bash
# ~/.authorized_keys base64 encoded key per line 1TGOop6cYn8meO0bOtnRbsQ4tfd0zRfGJhaMGCZVZ6M=
tftp-dus server 127.0.0.1:9000 /tmp --private-key `openssl rand -base64 32` --authorized-keys ~/.authorized_keys
```

#### Using encryption with client

Encryption is used based on `--encryption-level` argument (default: optional-protocol)
Client should be able to communicate even if the server does not support encryption.

client will exchange public keys and encrypt the traffic afterwards (client public key will be printed in the logs)

```bash
echo "hello" | tftp-dus send 127.0.0.1:9000 /dev/stdin --encryption-level protocol
```

client will exchange public keys and encrypt the data traffic

```bash
echo "hello" | tftp-dus send 127.0.0.1:9000 /dev/stdin --encryption-level data
```

if the server public key is known and `--encryption-level protocol` is used client will encrypt all traffic from the start

```bash
echo "hello" | tftp-dus send 127.0.0.1:9000 /dev/stdin --server-public-key 1TGOop6cYn8meO0bOtnRbsQ4tfd0zRfGJhaMGCZVZ6M= --encryption-level protocol
```

#### Allow port change if needed for third party tftp

server

```bash
tftp-dus server 127.0.0.1:9000 /tmp --require-server-port-change
```

client

```bash
echo "hello" | tftp-dus send 127.0.0.1:9000 /dev/stdin --allow-server-port-change
```

#### Receive directory list from the server

server

```bash
tftp-dus server 127.0.0.1:9000 /tmp --directory-list dir
```

client

```bash
tftp-dus receive 127.0.0.1:9000 subfolder/dir --local-path /dev/stdout
```

#### Uploading files created in a folder

```bash
tftp-dus sync 127.0.0.1:9000 /folder
```

Adding a user service to start on login

```bash
cat > ~/.config/systemd/tftp-sync-directory <<EOF
[Unit]
Description=tfp sync for directory to server

[Install]
WantedBy=default.target

[Service]
ExecStart=/usr/bin/tftp-dus sync server /directory
Restart=on-failure
EOF

systemctl --user start tftp-sync-directory
systemctl --user enable tftp-sync-directory
```

### Stats

```
                                             Send 100Mb
        +----------------------------------------------------------------------------------+
     18 |-+             +              +          +          +         +          +      +-|
        |                                                                                  |
        | x                                                                                |
        |                                                                                  |
     16 |-+                                                                              +-|
        |                                                                                  |
        |                                                                                  |
     14 |-+                                                                              +-|
        |                                                                                  |
        |                                                                                  |
     12 |-+                                                                              +-|
Time    |                                                                                  |
        |                                                                                  |
     10 |-+x                                                                             +-|
        |                                                                                  |
        |                                                                                  |
      8 |-+                                                                              +-|
        |     x                                                                            |
        |                                                                                  |
      6 |-+      x                                                                       +-|
        |            x  x                                                                  |
        |               +  x  x  x     +          +  x       +         +          +   x    |
      4 +----------------------------------------------------------------------------------+
        0               10             20         30         40        50         60
                                             WindowSize



                                             Receive 100Mb
        +----------------------------------------------------------------------------------+
     18 |-+             +              +          +          +         +          +      +-|
        |                                                                                  |
        | x                                                                                |
     16 |-+                                                                              +-|
        |                                                                                  |
     14 |-+                                                                              +-|
        |                                                                                  |
        |                                                                                  |
     12 |-+                                                                              +-|
        |                                                                                  |
        |  x                                                                               |
Time 10 |-+                                                                              +-|
        |                                                                                  |
        |                                                                                  |
      8 |-+                                                                              +-|
        |                                                                                  |
      6 |-+   x                                                                          +-|
        |                                                                                  |
        |        x   x                                                                     |
      4 |-+             x  x  x  x                                                       +-|
        |                                            x                                x    |
        |               +              +          +          +         +          +        |
      2 +----------------------------------------------------------------------------------+
        0               10             20         30         40        50         60
                                             WinddowSize

```

[More info](./info)
