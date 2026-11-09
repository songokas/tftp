// Included by the integration tests of the binaries, which define `BIN`.
// Packets and expected outcomes are in the `.packets` files next to this one.

use std::fs;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

const SERVER_FIRST_PACKET: &str = include_str!("server_first_packet.packets");
#[cfg(feature = "encryption")]
const SERVER_FIRST_PACKET_ENCRYPTION: &str =
    include_str!("server_first_packet_encryption.packets");
const SERVER_UPLOAD: &str = include_str!("server_upload.packets");
const SERVER_DOWNLOAD: &str = include_str!("server_download.packets");
const CLIENT_FIRST_REPLY: &str = include_str!("client_first_reply.packets");
const CLIENT_RECEIVE_TRANSFER: &str = include_str!("client_receive_transfer.packets");
const CLIENT_SEND_TRANSFER: &str = include_str!("client_send_transfer.packets");
const CLIENT_FOREIGN_SOURCE: &str = include_str!("client_foreign_source.packets");
const WINDOW_TRANSFER: &str = include_str!("window_transfer.packets");

const OP_DATA: u8 = 3;
const OP_ACK: u8 = 4;
const OP_ERROR: u8 = 5;
const OP_OACK: u8 = 6;

/// Long enough for a loopback reply, short enough to run many cases.
const REPLY_WAIT: Duration = Duration::from_millis(120);
const TRANSFER_WAIT: Duration = Duration::from_secs(3);
/// Above the client's request timeout, so that only a hang reaches it.
const EXIT_WAIT: Duration = Duration::from_secs(6);

const FIRST_BLOCK: [u8; 512] = [b'a'; 512];
const LAST_BLOCK: [u8; 10] = [b'b'; 10];

struct Case {
    name: String,
    outcome: String,
    bytes: Vec<u8>,
}

fn parse_cases(text: &str) -> Vec<Case> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.splitn(3, char::is_whitespace);
            let name = fields.next().unwrap().to_string();
            let rest = fields.next().unwrap_or_default();
            let (outcome, bytes) = match (rest, fields.next()) {
                ("", Some(more)) => {
                    let more = more.trim_start();
                    more.split_once(char::is_whitespace).unwrap_or((more, ""))
                }
                (outcome, more) => (outcome, more.unwrap_or_default()),
            };
            Case {
                bytes: parse_bytes(bytes),
                outcome: outcome.to_string(),
                name,
            }
        })
        .collect()
}

fn parse_bytes(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut rest = text.trim();
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('"') {
            let (value, after) = quoted.split_once('"').expect("unterminated string");
            bytes.extend_from_slice(value.as_bytes());
            rest = after.trim_start();
        } else {
            let (token, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            let (hex, count) = token.split_once('*').unwrap_or((token, "1"));
            let unit: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex byte"))
                .collect();
            for _ in 0..count.parse::<usize>().expect("invalid count") {
                bytes.extend_from_slice(&unit);
            }
            rest = after.trim_start();
        }
    }
    bytes
}

/// Runs every case and reports all failures together.
fn run_cases(file: &str, mut run: impl FnMut(usize, &Case) -> Result<(), String>) {
    let mut failures = Vec::new();
    for (index, case) in parse_cases(file).iter().enumerate() {
        if let Err(reason) = run(index, case) {
            failures.push(format!("{}: {reason}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn test_directory(name: &str) -> PathBuf {
    let directory =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ip-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

fn receive_datagram(socket: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    socket
        .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
        .unwrap();
    let mut buffer = [0; 70_000];
    let (size, from) = socket.recv_from(&mut buffer).ok()?;
    Some((buffer[..size].to_vec(), from))
}

fn localhost_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn ack(block: u16) -> Vec<u8> {
    let mut packet = vec![0, OP_ACK];
    packet.extend_from_slice(&block.to_be_bytes());
    packet
}

fn data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, OP_DATA];
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn request(opcode: u8, name: &str) -> Vec<u8> {
    let mut packet = vec![0, opcode];
    packet.extend_from_slice(name.as_bytes());
    packet.push(0);
    packet.extend_from_slice(b"octet\0");
    packet
}

fn opcode(packet: &[u8]) -> Option<u8> {
    (packet.len() >= 2 && packet[0] == 0).then(|| packet[1])
}

fn error_code(packet: &[u8]) -> Option<u16> {
    (opcode(packet) == Some(OP_ERROR) && packet.len() >= 4)
        .then(|| u16::from_be_bytes([packet[2], packet[3]]))
}

fn describe_exit(status: Option<ExitStatus>) -> String {
    status.map_or("still running".to_string(), |s| format!("{s}"))
}

struct Server {
    child: Child,
    port: u16,
    directory: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_server_port() -> u16 {
    static NEXT_OFFSET: AtomicU16 = AtomicU16::new(0);
    let base = 26_000 + (std::process::id() % 3_000) as u16;
    loop {
        let port = base + NEXT_OFFSET.fetch_add(1, Ordering::Relaxed);
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

impl Server {
    fn start(directory: &Path) -> Self {
        fs::write(directory.join("sample"), b"hello").unwrap();
        let port = free_server_port();
        let child = Command::new(BIN)
            .args(["server", &format!("127.0.0.1:{port}")])
            .arg(directory)
            .args(["--max-file-size", "4096", "--max-block-size", "512"])
            .args(["--max-window-size", "4", "--request-timeout", "2000"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let server = Self {
            child,
            port,
            directory: directory.to_path_buf(),
        };
        let deadline = Instant::now() + TRANSFER_WAIT;
        while !server.serves_a_file() {
            assert!(Instant::now() < deadline, "server did not start");
        }
        server
    }

    fn address(&self) -> SocketAddr {
        ([127, 0, 0, 1], self.port).into()
    }

    fn serves_a_file(&self) -> bool {
        let socket = localhost_socket();
        socket
            .send_to(&request(1, "sample"), self.address())
            .unwrap();
        match receive_datagram(&socket, REPLY_WAIT) {
            Some((packet, from)) if packet == data(1, b"hello") => {
                socket.send_to(&ack(1), from).unwrap();
                true
            }
            _ => false,
        }
    }

    /// `None` while it is healthy, otherwise what happened to it.
    fn problem(&mut self) -> Option<String> {
        if let Some(status) = self.child.try_wait().unwrap() {
            return Some(format!("server died with {status}"));
        }
        (!self.serves_a_file()).then(|| "server stopped answering".to_string())
    }
}

/// Every server case opens connections, and a finished one holds its slot until
/// the next cleanup, so a build with a few slots would run out of them.
const FEW_CONNECTION_SLOTS: bool = option_env!("TFTP_MAX_CLIENTS").is_some();

/// Runs cases against one server, replacing it if a case brings it down.
fn run_server_cases(
    file: &str,
    name: &str,
    mut exchange: impl FnMut(&Server, usize, &Case) -> Result<(), String>,
) {
    if FEW_CONNECTION_SLOTS {
        return;
    }
    let directory = test_directory(name);
    let mut server = Server::start(&directory);
    run_cases(file, |index, case| {
        let result = exchange(&server, index, case);
        if let Some(problem) = server.problem() {
            server = Server::start(&directory);
            return Err(problem);
        }
        result
    });
}

fn check_first_packet(server: &Server, case: &Case) -> Result<(), String> {
    let socket = localhost_socket();
    socket.send_to(&case.bytes, server.address()).unwrap();
    let reply = receive_datagram(&socket, REPLY_WAIT);
    if let Some((packet, from)) = &reply {
        if error_code(packet).is_none() {
            // let go of the connection this case opened
            socket
                .send_to(b"\0\x05\0\0done\0", from)
                .unwrap();
        }
    }
    let packet = reply.map(|(packet, _)| packet);
    let matches = match case.outcome.as_str() {
        "any" => true,
        "silent" => packet.is_none(),
        "accepted" => matches!(
            packet.as_deref().and_then(opcode),
            Some(OP_DATA | OP_OACK | OP_ACK)
        ),
        outcome => {
            let code = outcome.strip_prefix("error:").expect("unknown outcome");
            packet.as_deref().and_then(error_code) == code.parse().ok()
        }
    };
    if matches {
        Ok(())
    } else {
        Err(format!("expected {}, got {packet:02x?}", case.outcome))
    }
}

#[test]
fn test_server_first_packet() {
    run_server_cases(SERVER_FIRST_PACKET, "first", |server, _, case| {
        check_first_packet(server, case)
    });
}

#[cfg(feature = "encryption")]
#[test]
fn test_server_first_packet_with_encryption_options() {
    run_server_cases(
        SERVER_FIRST_PACKET_ENCRYPTION,
        "first-enc",
        |server, _, case| check_first_packet(server, case),
    );
}

fn wait_for_packet(
    socket: &UdpSocket,
    wait: Duration,
    wanted: impl Fn(&[u8]) -> bool,
) -> Option<SocketAddr> {
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        if let Some((packet, from)) = receive_datagram(socket, left) {
            if wanted(&packet) {
                return Some(from);
            }
        }
    }
    None
}

#[test]
fn test_server_during_upload() {
    run_server_cases(SERVER_UPLOAD, "upload", |server, index, case| {
        let socket = localhost_socket();
        let name = format!("upload-{index}");
        socket
            .send_to(&request(2, &name), server.address())
            .unwrap();
        let endpoint = wait_for_packet(&socket, TRANSFER_WAIT, |p| p == ack(0))
            .ok_or("no acknowledgement of the request")?;
        socket.send_to(&data(1, &FIRST_BLOCK), endpoint).unwrap();
        wait_for_packet(&socket, TRANSFER_WAIT, |p| p == ack(1))
            .ok_or("no acknowledgement of block 1")?;

        socket.send_to(&case.bytes, endpoint).unwrap();
        sleep(Duration::from_millis(10));

        socket.send_to(&data(2, &LAST_BLOCK), endpoint).unwrap();
        let finished = wait_for_packet(&socket, REPLY_WAIT * 3, |p| p == ack(2)).is_some();
        match case.outcome.as_str() {
            "abort" if finished => Err("transfer carried on".to_string()),
            "abort" => Ok(()),
            _ if !finished => Err("no acknowledgement of the last block".to_string()),
            _ => {
                let stored = fs::read(server.directory.join(&name)).unwrap_or_default();
                let expected = [FIRST_BLOCK.as_slice(), LAST_BLOCK.as_slice()].concat();
                (stored == expected)
                    .then_some(())
                    .ok_or(format!("stored {} bytes differ", stored.len()))
            }
        }
    });
}

#[test]
fn test_server_during_download() {
    if FEW_CONNECTION_SLOTS {
        return;
    }
    let file: Vec<u8> = (0..1300_u32).map(|i| (i % 251) as u8).collect();
    let directory = test_directory("download");
    let mut server = Server::start(&directory);
    fs::write(directory.join("large"), &file).unwrap();
    run_cases(SERVER_DOWNLOAD, |_, case| {
        let result = (|| {
            let socket = localhost_socket();
            socket
                .send_to(&request(1, "large"), server.address())
                .unwrap();
            let (first, endpoint) =
                receive_datagram(&socket, TRANSFER_WAIT).ok_or("no first block")?;
            if first != data(1, &file[..512]) {
                return Err(format!("unexpected first packet {:02x?}", &first[..4]));
            }

            socket.send_to(&case.bytes, endpoint).unwrap();
            sleep(Duration::from_millis(10));
            socket.send_to(&ack(1), endpoint).unwrap();

            let mut received = first[4..].to_vec();
            let mut block = 2_u16;
            let finished = loop {
                let expected = block;
                let Some((packet, _)) = receive_until(&socket, expected) else {
                    break false;
                };
                received.extend_from_slice(&packet[4..]);
                socket.send_to(&ack(block), endpoint).unwrap();
                if packet.len() - 4 < 512 {
                    break true;
                }
                block += 1;
            };
            match case.outcome.as_str() {
                "abort" if block > 2 || finished => Err("transfer carried on".to_string()),
                "abort" => Ok(()),
                _ if !finished => Err(format!("stalled before block {block}")),
                _ => (received == file)
                    .then_some(())
                    .ok_or("received data differs".to_string()),
            }
        })();
        if let Some(problem) = server.problem() {
            server = Server::start(&directory);
            return Err(problem);
        }
        result
    });
}

/// Skips retransmissions and anything else that is not data block `block`.
fn receive_until(socket: &UdpSocket, block: u16) -> Option<(Vec<u8>, SocketAddr)> {
    let deadline = Instant::now() + REPLY_WAIT * 4;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        if let Some((packet, from)) = receive_datagram(socket, left) {
            if packet.len() >= 4 && packet[..4] == data(block, &[])[..4] {
                return Some((packet, from));
            }
        }
    }
    None
}

fn windowed_file() -> Vec<u8> {
    (0..3200_u32).map(|i| (i % 251) as u8).collect()
}

/// With blocks 1 to 4 of a window on their way and block 2 lost, sends `bad_ack`
/// and then has the peer at `endpoint` deliver the rest of the file.
fn finish_window_with_lost_block(
    socket: &UdpSocket,
    endpoint: SocketAddr,
    bad_ack: &[u8],
) -> Result<Vec<u8>, String> {
    let mut received = Vec::new();
    for block in 1..=4 {
        let (packet, _) = receive_until(socket, block).ok_or(format!("no block {block}"))?;
        if block == 1 {
            received.extend_from_slice(&packet[4..]);
        }
    }

    socket.send_to(bad_ack, endpoint).unwrap();
    sleep(Duration::from_millis(10));
    socket.send_to(&ack(1), endpoint).unwrap();

    let mut block = 2_u16;
    loop {
        let (packet, _) =
            receive_until(socket, block).ok_or(format!("block {block} was not sent again"))?;
        received.extend_from_slice(&packet[4..]);
        socket.send_to(&ack(block), endpoint).unwrap();
        if packet.len() - 4 < 512 {
            return Ok(received);
        }
        block += 1;
    }
}

#[test]
fn test_server_keeps_unacknowledged_blocks_of_a_window() {
    if FEW_CONNECTION_SLOTS {
        return;
    }
    let file = windowed_file();
    let directory = test_directory("download-window");
    let server = Server::start(&directory);
    fs::write(directory.join("large"), &file).unwrap();
    run_cases(WINDOW_TRANSFER, |_, case| {
        let socket = localhost_socket();
        let mut windowed = request(1, "large");
        windowed.extend_from_slice(b"windowsize\x004\0");
        socket.send_to(&windowed, server.address()).unwrap();
        let endpoint = wait_for_packet(&socket, TRANSFER_WAIT, |p| opcode(p) == Some(OP_OACK))
            .ok_or("no reply to the request")?;
        socket.send_to(&ack(0), endpoint).unwrap();

        let received = finish_window_with_lost_block(&socket, endpoint, &case.bytes)?;
        (received == file)
            .then_some(())
            .ok_or("received data differs".to_string())
    });
}

#[test]
fn test_client_send_keeps_unacknowledged_blocks_of_a_window() {
    let directory = test_directory("send-window");
    let file = directory.join("upload");
    let contents = windowed_file();
    fs::write(&file, &contents).unwrap();
    run_cases(WINDOW_TRANSFER, |_, case| {
        let peer = localhost_socket();
        let client = ClientRun::start(send_command(&peer, "512", "4", &file));
        let (_, endpoint) =
            receive_datagram(&peer, TRANSFER_WAIT).ok_or("no request from client")?;
        peer.send_to(b"\0\x06windowsize\x004\0", endpoint).unwrap();

        let received = finish_window_with_lost_block(&peer, endpoint, &case.bytes)?;
        let (status, _) = client.finish(&peer);
        if status.and_then(|s| s.code()) != Some(0) {
            return Err(format!("expected exit 0, got {}", describe_exit(status)));
        }
        (received == contents)
            .then_some(())
            .ok_or("sent data differs".to_string())
    });
}

fn client_command(command: &str, peer: &UdpSocket, block_size: &str, window_size: &str) -> Command {
    let mut client = Command::new(BIN);
    client
        .args([command, &peer.local_addr().unwrap().to_string()])
        .args(["--listen", "127.0.0.1:0", "--request-timeout", "1000"])
        .args(["--block-size", block_size, "--window-size", window_size])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if cfg!(feature = "encryption") {
        client.args(["--encryption-level", "none"]);
    }
    client
}

fn receive_command(peer: &UdpSocket, block_size: &str, window_size: &str, file: &Path) -> Command {
    let mut client = client_command("receive", peer, block_size, window_size);
    client.arg("remote").arg("--local-path").arg(file);
    client
}

fn send_command(peer: &UdpSocket, block_size: &str, window_size: &str, file: &Path) -> Command {
    let mut client = client_command("send", peer, block_size, window_size);
    client.arg(file).args(["--remote-path", "remote"]);
    client
}

struct ClientRun {
    child: Child,
}

impl ClientRun {
    fn start(mut command: Command) -> Self {
        Self {
            child: command.spawn().unwrap(),
        }
    }

    /// Waits for the client to exit while collecting what it sends to `peer`.
    fn finish(mut self, peer: &UdpSocket) -> (Option<ExitStatus>, Vec<Vec<u8>>) {
        let deadline = Instant::now() + EXIT_WAIT;
        let mut sent = Vec::new();
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                while let Some((packet, _)) = receive_datagram(peer, Duration::from_millis(1)) {
                    sent.push(packet);
                }
                return (Some(status), sent);
            }
            if let Some((packet, _)) = receive_datagram(peer, Duration::from_millis(20)) {
                sent.push(packet);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        (None, sent)
    }
}

fn check_failed_exit(
    case: &Case,
    status: Option<ExitStatus>,
    sent: &[Vec<u8>],
) -> Result<(), String> {
    if status.and_then(|s| s.code()) != Some(1) {
        return Err(format!("expected exit 1, got {}", describe_exit(status)));
    }
    if let Some(code) = case.outcome.strip_prefix("fail:") {
        let code: u16 = code.parse().expect("invalid error code");
        if !sent.iter().any(|p| error_code(p) == Some(code)) {
            return Err(format!("client did not send error {code}"));
        }
    }
    Ok(())
}

fn check_first_reply(mut command: Command, peer: &UdpSocket, case: &Case) -> Result<(), String> {
    command.stdout(Stdio::null());
    let client = ClientRun::start(command);
    let (_, endpoint) = receive_datagram(peer, TRANSFER_WAIT).ok_or("no request from client")?;
    peer.send_to(&case.bytes, endpoint).unwrap();
    let (status, sent) = client.finish(peer);
    check_failed_exit(case, status, &sent)
}

#[test]
fn test_client_receive_first_reply() {
    let directory = test_directory("receive-reply");
    run_cases(CLIENT_FIRST_REPLY, |index, case| {
        let peer = localhost_socket();
        let file = directory.join(index.to_string());
        check_first_reply(receive_command(&peer, "400", "4", &file), &peer, case)
    });
}

#[test]
fn test_client_send_first_reply() {
    let directory = test_directory("send-reply");
    let file = directory.join("upload");
    fs::write(&file, b"hello").unwrap();
    run_cases(CLIENT_FIRST_REPLY, |_, case| {
        let peer = localhost_socket();
        check_first_reply(send_command(&peer, "400", "4", &file), &peer, case)
    });
}

/// Receives a two block file, with `inject` running after block 1.
fn receive_transfer(
    file: &Path,
    case: &Case,
    inject: impl FnOnce(&UdpSocket, SocketAddr),
) -> Result<(), String> {
    let peer = localhost_socket();
    let client = ClientRun::start(receive_command(&peer, "512", "1", file));
    let (_, endpoint) = receive_datagram(&peer, TRANSFER_WAIT).ok_or("no request from client")?;
    peer.send_to(&data(1, &FIRST_BLOCK), endpoint).unwrap();
    wait_for_packet(&peer, TRANSFER_WAIT, |p| p == ack(1)).ok_or("block 1 was not acknowledged")?;

    inject(&peer, endpoint);
    sleep(Duration::from_millis(10));

    if case.outcome != "ignored" {
        let (status, sent) = client.finish(&peer);
        return check_failed_exit(case, status, &sent);
    }

    peer.send_to(&data(2, &LAST_BLOCK), endpoint).unwrap();
    let (status, _) = client.finish(&peer);
    if status.and_then(|s| s.code()) != Some(0) {
        return Err(format!("expected exit 0, got {}", describe_exit(status)));
    }
    let stored = fs::read(file).unwrap_or_default();
    let expected = [FIRST_BLOCK.as_slice(), LAST_BLOCK.as_slice()].concat();
    (stored == expected)
        .then_some(())
        .ok_or(format!("stored {} bytes differ", stored.len()))
}

/// Sends a two block file, with `inject` running after block 1 arrived.
fn send_transfer(
    file: &Path,
    case: &Case,
    inject: impl FnOnce(&UdpSocket, SocketAddr),
) -> Result<(), String> {
    let peer = localhost_socket();
    let client = ClientRun::start(send_command(&peer, "512", "1", file));
    let (_, endpoint) = receive_datagram(&peer, TRANSFER_WAIT).ok_or("no request from client")?;
    peer.send_to(&ack(0), endpoint).unwrap();
    let first = receive_until(&peer, 1).ok_or("no block 1")?;

    inject(&peer, endpoint);
    sleep(Duration::from_millis(10));

    if case.outcome != "ignored" {
        let (status, sent) = client.finish(&peer);
        return check_failed_exit(case, status, &sent);
    }

    peer.send_to(&ack(1), endpoint).unwrap();
    let second = receive_until(&peer, 2).ok_or("no block 2")?;
    peer.send_to(&ack(2), endpoint).unwrap();
    let (status, _) = client.finish(&peer);
    if status.and_then(|s| s.code()) != Some(0) {
        return Err(format!("expected exit 0, got {}", describe_exit(status)));
    }
    let sent = [&first.0[4..], &second.0[4..]].concat();
    (sent == fs::read(file).unwrap())
        .then_some(())
        .ok_or(format!("sent {} bytes differ", sent.len()))
}

fn upload_file(directory: &Path) -> PathBuf {
    let file = directory.join("upload");
    fs::write(
        &file,
        [FIRST_BLOCK.as_slice(), LAST_BLOCK.as_slice()].concat(),
    )
    .unwrap();
    file
}

#[test]
fn test_client_during_receive() {
    let directory = test_directory("receive-transfer");
    run_cases(CLIENT_RECEIVE_TRANSFER, |index, case| {
        let file = directory.join(index.to_string());
        receive_transfer(&file, case, |peer, endpoint| {
            peer.send_to(&case.bytes, endpoint).unwrap();
        })
    });
}

#[test]
fn test_client_during_send() {
    let directory = test_directory("send-transfer");
    let file = upload_file(&directory);
    run_cases(CLIENT_SEND_TRANSFER, |_, case| {
        send_transfer(&file, case, |peer, endpoint| {
            peer.send_to(&case.bytes, endpoint).unwrap();
        })
    });
}

#[test]
fn test_client_receive_ignores_other_sources() {
    let directory = test_directory("receive-foreign");
    run_cases(CLIENT_FOREIGN_SOURCE, |index, case| {
        let file = directory.join(index.to_string());
        receive_transfer(&file, case, |_, endpoint| {
            localhost_socket().send_to(&case.bytes, endpoint).unwrap();
        })
    });
}

#[test]
fn test_client_send_ignores_other_sources() {
    let directory = test_directory("send-foreign");
    let file = upload_file(&directory);
    run_cases(CLIENT_FOREIGN_SOURCE, |_, case| {
        send_transfer(&file, case, |_, endpoint| {
            localhost_socket().send_to(&case.bytes, endpoint).unwrap();
        })
    });
}
