# Invalid packet cases

`invalid_packets.rs` runs the real binaries over UDP while the test plays the
other side. It is included by `std-binary/tests/invalid_packets.rs` and
`std-stack-binary/tests/invalid_packets.rs`.

Each line of a `.packets` file is `name outcome bytes`:

- bytes are hex and `"quoted text"`; `ff*600` and `c3a9*60` repeat bytes
- no bytes means an empty datagram
- `#` starts a comment line

| Outcome | Meaning |
|---|---|
| `silent` | the server does not reply |
| `error:N` | the server replies with TFTP error `N` |
| `accepted` | the server starts a transfer |
| `any` | the reply differs between builds; the server only has to survive |
| `ignored` | the transfer carries on and the file is intact |
| `abort` | the server ends the transfer |
| `fail` | the client exits with status 1 |
| `fail:N` | same, and the client first sends TFTP error `N` |

Every server case also checks that the server is still running and can serve a
file afterwards. A panic is a failure: status 101, or SIGABRT in the stack only
binary.

| File | When the packet is sent |
|---|---|
| `server_first_packet` | as the first datagram to the server's port |
| `server_first_packet_encryption` | same, only in builds with `encryption` |
| `server_upload` | after block 1 of an upload was acknowledged |
| `server_download` | after block 1 of a download was received |
| `client_first_reply` | as the reply to the client's request, for send and receive |
| `window_transfer` | with window size 4, when blocks 1 to 4 were sent and block 2 was lost, for a server download and a client upload |
| `client_receive_transfer` | after the client acknowledged block 1 |
| `client_send_transfer` | after the client sent block 1 |
| `client_foreign_source` | during a transfer, from a port that is not the server's |
