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
- optional stack only functionality (currently lib only)
- compatible with third party clients,servers
- large file support
- ability to synchronize new files in a folder

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
