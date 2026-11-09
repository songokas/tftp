//! The binary aborts on any heap allocation, so each successful transfer here
//! also shows that the exercised path stays off the heap.

use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::thread::sleep;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_tftp-dus-stack-only");
const SIGABRT_EXIT: Option<i32> = None;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn directories(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&root);
    let (server, client) = (root.join("server"), root.join("client"));
    fs::create_dir_all(&server).unwrap();
    fs::create_dir_all(&client).unwrap();
    (server, client)
}

/// Tests run in parallel and servers share ports with `SO_REUSEPORT`, so a port
/// that another run or test is using could reach the wrong server. These come
/// from below the ephemeral range, and each is handed out once per process.
fn get_port() -> u16 {
    static NEXT_OFFSET: AtomicU16 = AtomicU16::new(0);
    let base = 20_000 + (std::process::id() % 5_000) as u16;
    loop {
        let port = base + NEXT_OFFSET.fetch_add(1, Ordering::Relaxed);
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn start_server(port: u16, directory: &PathBuf, extra: &[&str]) -> Server {
    let child = Command::new(BIN)
        .args(["server", &format!("127.0.0.1:{port}")])
        .arg(directory)
        .args(extra)
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(300));
    Server(child)
}

fn client(command: &str, port: u16, paths: &[&str], extra: &[&str]) -> Output {
    Command::new(BIN)
        .args([command, &format!("127.0.0.1:{port}")])
        .args(paths)
        .args(["--listen", "127.0.0.1:0", "--request-timeout", "5000"])
        .args(extra)
        .output()
        .unwrap()
}

fn without_encryption<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut arguments = Vec::new();
    if cfg!(feature = "encryption") {
        arguments.extend(["--encryption-level", "none"]);
    }
    arguments.extend_from_slice(extra);
    arguments
}

fn sample_data() -> Vec<u8> {
    (0..300_000_u32).map(|i| (i % 251) as u8).collect()
}

fn assert_round_trip(name: &str, port: u16, server_extra: &[&str], client_extra: &[&str]) {
    let (server_dir, client_dir) = directories(name);
    let _server = start_server(port, &server_dir, server_extra);

    let data = sample_data();
    let upload = client_dir.join("upload");
    fs::write(&upload, &data).unwrap();
    let sent = client(
        "send",
        port,
        &[upload.to_str().unwrap(), "--remote-path", "nested/stored"],
        client_extra,
    );
    assert!(sent.status.success(), "{sent:?}");
    assert_eq!(fs::read(server_dir.join("nested/stored")).unwrap(), data);

    let download = client_dir.join("download");
    let received = client(
        "receive",
        port,
        &["nested/stored", "--local-path", download.to_str().unwrap()],
        client_extra,
    );
    assert!(received.status.success(), "{received:?}");
    assert_eq!(fs::read(download).unwrap(), data);
}

#[test]
fn test_round_trip_without_encryption() {
    assert_round_trip(
        "plain",
        get_port(),
        &[],
        &without_encryption(&["--window-size", "4"]),
    );
}

#[test]
fn test_round_trip_with_negotiated_encryption() {
    assert_round_trip("negotiated", get_port(), &[], &[]);
}

#[cfg(feature = "encryption")]
#[test]
fn test_round_trip_with_authorized_keys() {
    let client_private = "t4JQnsfYIIcah6RMAnetDTjtV7OyQ+sAXMnBV68tvfY=";
    let client_public = "Ww+C2l/aCJPoNvnB8YKNibUCaGITFRp/lnowz8Rpai0=";
    let server_private = "XnXn2SAxtXlUAXlobJsCW9BRg6XKNcKCS4XNoaMjJJk=";
    let server_public = "q62LxBAfk9i8EszckOMbEL731AxryOuHcrTQHmXzjWg=";
    let authorized = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("authorized-keys");
    fs::write(&authorized, format!("# clients\n\n{client_public}\n")).unwrap();
    assert_round_trip(
        "authorized",
        get_port(),
        &[
            "--private-key",
            server_private,
            "--authorized-keys",
            authorized.to_str().unwrap(),
        ],
        &[
            "--encryption-level",
            "protocol",
            "--private-key",
            client_private,
            "--server-public-key",
            server_public,
        ],
    );
}

#[test]
fn test_symlink_cannot_escape_server_directory() {
    let (server_dir, client_dir) = directories("symlink");
    let outside = client_dir.join("secret");
    fs::write(&outside, b"secret").unwrap();
    std::os::unix::fs::symlink(&outside, server_dir.join("link")).unwrap();
    let port = get_port();
    let _server = start_server(port, &server_dir, &[]);

    let download = client_dir.join("download");
    let received = client(
        "receive",
        port,
        &["link", "--local-path", download.to_str().unwrap()],
        &without_encryption(&[]),
    );
    assert!(!received.status.success(), "{received:?}");
    assert_ne!(received.status.code(), SIGABRT_EXIT, "{received:?}");
    assert_ne!(fs::read(download).unwrap_or_default(), b"secret");
}

#[test]
fn test_missing_file_reports_error_without_heap() {
    let (server_dir, client_dir) = directories("missing");
    let port = get_port();
    let _server = start_server(port, &server_dir, &[]);
    let download = client_dir.join("download");
    let received = client(
        "receive",
        port,
        &["absent", "--local-path", download.to_str().unwrap()],
        &without_encryption(&[]),
    );
    assert_eq!(received.status.code(), Some(1), "{received:?}");
}

#[test]
fn test_concurrent_transfers() {
    let (server_dir, client_dir) = directories("concurrent");
    let data = sample_data();
    fs::write(server_dir.join("shared"), &data).unwrap();
    let port = get_port();
    let _server = start_server(port, &server_dir, &[]);

    std::thread::scope(|scope| {
        let transfers: Vec<_> = (0..8)
            .map(|index| {
                let download = client_dir.join(format!("download-{index}"));
                scope.spawn(move || {
                    let received = client(
                        "receive",
                        port,
                        &["shared", "--local-path", download.to_str().unwrap()],
                        &without_encryption(&[]),
                    );
                    assert!(received.status.success(), "{received:?}");
                    download
                })
            })
            .collect();
        for transfer in transfers {
            assert_eq!(fs::read(transfer.join().unwrap()).unwrap(), data);
        }
    });
}

#[test]
fn test_connection_slots_are_reused() {
    let (server_dir, client_dir) = directories("slots");
    fs::write(server_dir.join("small"), b"small").unwrap();
    let port = get_port();
    let _server = start_server(port, &server_dir, &["--max-connections", "2"]);

    for index in 0..6 {
        let download = client_dir.join(format!("download-{index}"));
        let received = client(
            "receive",
            port,
            &["small", "--local-path", download.to_str().unwrap()],
            &without_encryption(&[]),
        );
        assert!(received.status.success(), "{received:?}");
        assert_eq!(fs::read(download).unwrap(), b"small");
    }
}

#[test]
fn test_usage_error_and_hostname_rejected() {
    let usage = Command::new(BIN).arg("nonsense").output().unwrap();
    assert_eq!(usage.status.code(), Some(2));

    let hostname = Command::new(BIN)
        .args(["receive", "localhost:9", "a"])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(1), "{hostname:?}");
}

#[test]
fn test_help_prints_to_stdout() {
    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
}
