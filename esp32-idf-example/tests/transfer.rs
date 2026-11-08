//! Real `tftp-dus` transfers over loopback with the sockets and storage of the example.

use std::fs;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::thread::spawn;
use std::time::Duration;
use std::time::Instant;

use rand::rngs::OsRng;
use tftp_dus::client::receive_file;
use tftp_dus::client::send_file;
use tftp_dus::client::ClientConfig;
use tftp_dus::config::ConnectionOptions;
use tftp_dus::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp_dus::encryption::EncryptionLevel;
use tftp_dus::error::BoxedResult;
use tftp_dus::socket::Socket;
use tftp_dus::types::DataBuffer;
use tftp_dus::types::FilePath;
use tftp_esp32_idf_example::net::create_socket;
use tftp_esp32_idf_example::serve;
use tftp_esp32_idf_example::server_config;
use tftp_esp32_idf_example::MAX_BLOCK_SIZE;
use tftp_esp32_idf_example::MAX_CONNECTIONS;
use tftp_esp32_idf_example::MAX_WINDOW_SIZE;

struct Server {
    address: SocketAddr,
    directory: PathBuf,
}

fn free_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn start_server(name: &str, allow_overwrite: bool) -> Server {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();

    let address = free_port();
    let mut config = server_config(address, directory.to_str().unwrap());
    config.allow_overwrite = allow_overwrite;
    config.request_timeout = Duration::from_secs(2);
    drop(spawn(move || serve(config).map_err(|e| e.to_string())));
    std::thread::sleep(Duration::from_millis(50));
    Server { address, directory }
}

fn client_config(server: &Server) -> ClientConfig {
    ClientConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        endpoint: server.address,
        request_timeout: Duration::from_secs(2),
        max_file_size: 16 * 1024 * 1024,
        private_key: None,
        remote_public_key: None,
        allow_server_port_change: true,
        prefer_seek: false,
        encryption_key: None,
    }
}

fn options(block_size: u16, window_size: u16, file_size: Option<u64>) -> ConnectionOptions {
    ConnectionOptions {
        block_size,
        retry_packet_after_timeout: DEFAULT_RETRY_PACKET_TIMEOUT,
        file_size,
        encryption_level: EncryptionLevel::None,
        window_size,
    }
}

fn sample(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

fn download(
    server: &Server,
    remote: &str,
    block_size: u16,
    window_size: u16,
) -> BoxedResult<Vec<u8>> {
    let local = server.directory.join(format!("downloaded-{remote}"));
    let local = PathBuf::from(format!("{}.local", local.display()));
    let config = client_config(server);
    let socket = create_socket(config.listen, 1)?;
    let local_path = local.clone();
    receive_file(
        config,
        local.to_str().unwrap().into(),
        remote.into(),
        options(block_size, window_size, Some(0)),
        move |_| Ok(fs::File::create(&local_path)?),
        socket,
        Instant::now,
        OsRng,
    )?;
    Ok(fs::read(local)?)
}

fn upload(
    server: &Server,
    remote: &str,
    data: &[u8],
    block_size: u16,
    window_size: u16,
) -> BoxedResult<usize> {
    let local = server.directory.join("upload-source.local");
    fs::write(&local, data)?;
    let config = client_config(server);
    let socket = create_socket(config.listen, 1)?;
    let local_path = local.clone();
    let (sent, _) = send_file(
        config,
        local.to_str().unwrap().into(),
        remote.into(),
        options(block_size, window_size, Some(data.len() as u64)),
        move |_: &FilePath| {
            let file = fs::File::open(&local_path)?;
            Ok((Some(file.metadata()?.len()), file))
        },
        socket,
        Instant::now,
        OsRng,
    )?;
    Ok(sent)
}

fn round_trip(name: &str, block_size: u16, window_size: u16, length: usize) {
    let server = start_server(name, true);
    let data = sample(length);

    assert_eq!(
        upload(&server, "stored", &data, block_size, window_size).unwrap(),
        length
    );
    assert_eq!(fs::read(server.directory.join("stored")).unwrap(), data);
    assert_eq!(
        download(&server, "stored", block_size, window_size).unwrap(),
        data
    );
}

#[test]
fn round_trip_with_window_of_one() {
    round_trip("window-one", 512, 1, 5000);
}

#[test]
fn round_trip_with_largest_window_and_block() {
    round_trip(
        "largest",
        MAX_BLOCK_SIZE,
        MAX_WINDOW_SIZE,
        200 * MAX_BLOCK_SIZE as usize + 17,
    );
}

#[test]
fn round_trip_of_exact_block_multiple() {
    round_trip("block-multiple", 512, 4, 2048);
}

#[test]
fn concurrent_clients_up_to_the_limit() {
    let server = start_server("concurrent", true);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..MAX_CONNECTIONS)
            .map(|i| {
                let server = &server;
                scope.spawn(move || {
                    let name = format!("file-{i}");
                    let data = vec![i as u8; 64 * 1024];
                    let config = client_config(server);
                    let socket = create_socket(config.listen, 1).unwrap();
                    let local = server.directory.join(format!("{name}.local"));
                    fs::write(&local, &data).unwrap();
                    send_file(
                        config,
                        local.to_str().unwrap().into(),
                        name.as_str().into(),
                        options(MAX_BLOCK_SIZE, MAX_WINDOW_SIZE, Some(data.len() as u64)),
                        |_: &FilePath| {
                            let file = fs::File::open(&local)?;
                            Ok((Some(file.metadata()?.len()), file))
                        },
                        socket,
                        Instant::now,
                        OsRng,
                    )
                    .map_err(|e| e.to_string())
                    .unwrap();
                    (name, data)
                })
            })
            .collect();
        for handle in handles {
            let (name, data) = handle.join().unwrap();
            assert_eq!(fs::read(server.directory.join(name)).unwrap(), data);
        }
    });
}

#[test]
fn missing_file_is_reported() {
    let server = start_server("missing", true);
    assert!(download(&server, "absent", 512, 1).is_err());
}

#[test]
fn parent_directories_can_not_escape_the_served_directory() {
    let server = start_server("outside", true);
    let outside = server.directory.with_file_name("outside-file");
    fs::write(&outside, b"outside").unwrap();

    upload(&server, "../outside-file", b"changed", 512, 1).unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert_eq!(
        fs::read(server.directory.join("outside-file")).unwrap(),
        b"changed"
    );
}

#[test]
fn subdirectories_are_rejected() {
    let server = start_server("subdirectory", true);
    assert!(upload(&server, "folder/file", b"data", 512, 1).is_err());
    assert!(!server.directory.join("folder").exists());
}

#[test]
fn existing_file_is_kept_without_overwrite() {
    let server = start_server("keep", false);
    fs::write(server.directory.join("existing"), b"original").unwrap();

    assert!(upload(&server, "existing", b"replacement", 512, 1).is_err());
    assert_eq!(
        fs::read(server.directory.join("existing")).unwrap(),
        b"original"
    );
}

#[test]
fn socket_wait_follows_the_requested_duration() {
    let mut socket = create_socket("127.0.0.1:0".parse().unwrap(), 1).unwrap();
    let mut buffer: DataBuffer = vec![0; 32];

    for _ in 0..2 {
        let started = Instant::now();
        let error = socket.recv_from(&mut buffer, None).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(started.elapsed() < Duration::from_millis(25));

        let wait = Duration::from_millis(50);
        let started = Instant::now();
        let error = socket.recv_from(&mut buffer, Some(wait)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= wait);
    }
}
