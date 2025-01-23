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
wget https://github.com/songokas/tftp/releases/download/v0.6.0/tftp-dus_0.6.0_amd64.deb \
  && sudo apt install ./tftp-dus_0.6.0_amd64.deb
```

Download binary

https://github.com/songokas/tftp/releases

Install from source

```bash
cargo install --bins --root=. --git=https://github.com/songokas/tftp
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
