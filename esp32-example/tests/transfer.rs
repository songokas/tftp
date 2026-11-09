//! Real `tftp-dus` transfers between two smoltcp stacks linked by a channel.

#![allow(clippy::result_large_err)]

use std::collections::VecDeque;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::OnceLock;
use std::thread::spawn;
use std::time::Duration;
use std::time::Instant as StdInstant;

use rand::CryptoRng;
use rand::RngCore;
use smoltcp::phy::Device;
use smoltcp::phy::DeviceCapabilities;
use smoltcp::phy::Medium;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use tftp_dus::client::receive_file;
use tftp_dus::client::send_file;
use tftp_dus::client::ClientConfig;
use tftp_dus::config::ConnectionOptions;
use tftp_dus::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp_dus::config::MAX_BLOCKS_FOR_MULTI_READER;
use tftp_dus::config::MAX_CLIENTS;
use tftp_dus::config::PREFERRED_DATA_BLOCK_SIZE;
use tftp_dus::encryption::EncryptionLevel;
use tftp_dus::server::server;
use tftp_dus::server::ServerConfig;
use tftp_dus::std_compat::io::ErrorKind;
use tftp_dus::std_compat::io::Write;
use tftp_dus::std_compat::time::Instant;
use tftp_esp32_example::net::Address;
use tftp_esp32_example::net::Memory;
use tftp_esp32_example::net::NetStack;
use tftp_esp32_example::storage::RamDisk;
use tftp_esp32_example::storage::FILE_CAPACITY;

const SERVER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

#[derive(Clone, Copy)]
struct TestRng;

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        4
    }

    fn next_u64(&mut self) -> u64 {
        4
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(4);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(4);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct Link {
    outgoing: Sender<Vec<u8>>,
    incoming: Receiver<Vec<u8>>,
    pending: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx(Sender<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        let _ = self.0.send(frame);
        result
    }
}

impl Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;

    fn receive(&mut self, _timestamp: NetInstant) -> Option<(Rx, Tx)> {
        self.pending.extend(self.incoming.try_iter());
        let frame = self.pending.pop_front()?;
        Some((Rx(frame), Tx(self.outgoing.clone())))
    }

    fn transmit(&mut self, _timestamp: NetInstant) -> Option<Tx> {
        Some(Tx(self.outgoing.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1514;
        capabilities
    }
}

fn microseconds() -> u64 {
    static START: OnceLock<StdInstant> = OnceLock::new();
    START.get_or_init(StdInstant::now).elapsed().as_micros() as u64
}

fn instant() -> Instant {
    Instant::from_time(microseconds)
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

fn new_stack(link: Link, mac: [u8; 6], last_octet: u8) -> &'static NetStack<Link> {
    let address = Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, last_octet), 24);
    leak(NetStack::new(
        link,
        mac,
        Address::Static(address),
        Box::leak(Box::new(Memory::new())),
        microseconds,
        u64::from(last_octet),
    ))
}

/// Each stack is created on the thread that uses it, as `NetStack` is not Sync.
fn start_server(port: u16, link: Link, disk: &'static RamDisk) {
    let thread = spawn(move || {
        let stack = new_stack(link, SERVER_MAC, 1);
        let config = ServerConfig {
            listen: format!("10.0.0.1:{port}").parse().unwrap(),
            directory: "/".parse().unwrap(),
            allow_overwrite: false,
            max_window_size: MAX_BLOCKS_FOR_MULTI_READER,
            request_timeout: Duration::from_secs(5),
            max_connections: MAX_CLIENTS,
            max_file_size: FILE_CAPACITY as u64,
            max_block_size: PREFERRED_DATA_BLOCK_SIZE,
            authorized_keys: None,
            private_key: None,
            require_full_encryption: false,
            require_server_port_change: true,
            prefer_seek: false,
            directory_list: None,
            max_directory_depth: 0,
            error_to_authorized_only: false,
        };
        let _ = server(
            config,
            |path, _config| disk.open(path),
            |path, config| disk.create(path, config.allow_overwrite),
            |listen, id, _reuse, _capacity| stack.create_socket(listen, id),
            |listen, id, client| stack.create_bound_socket(listen, id, client),
            instant,
            TestRng,
        );
    });
    drop(thread);
}

fn links() -> (Link, Link) {
    let (to_server, from_client) = channel();
    let (to_client, from_server) = channel();
    let server = Link {
        outgoing: to_client,
        incoming: from_client,
        pending: VecDeque::new(),
    };
    let client = Link {
        outgoing: to_server,
        incoming: from_server,
        pending: VecDeque::new(),
    };
    (server, client)
}

fn client_config(port: u16, local_port: u16) -> ClientConfig {
    ClientConfig {
        listen: format!("10.0.0.2:{local_port}").parse().unwrap(),
        endpoint: format!("10.0.0.1:{port}").parse().unwrap(),
        request_timeout: Duration::from_secs(5),
        max_file_size: FILE_CAPACITY as u64,
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

fn round_trip(port: u16, block_size: u16, window_size: u16, length: usize) {
    let (server_link, client_link) = links();
    let server_disk: &'static RamDisk = leak(RamDisk::new());
    let client_disk: &'static RamDisk = leak(RamDisk::new());
    let data = sample(length);
    assert!(server_disk.insert("download", &data));
    assert!(client_disk.insert("upload", &data));
    start_server(port, server_link, server_disk);

    let stack = new_stack(client_link, CLIENT_MAC, 2);

    let config = client_config(port, 5000);
    let socket = stack.create_socket(config.listen, 1).unwrap();
    let (received, _) = receive_file(
        config,
        "local".parse().unwrap(),
        "download".parse().unwrap(),
        options(block_size, window_size, Some(0)),
        |path| client_disk.create(path, false),
        socket,
        instant,
        TestRng,
    )
    .unwrap();
    assert_eq!(received, length);
    assert_eq!(client_disk.contents("local", <[u8]>::to_vec).unwrap(), data);

    let config = client_config(port, 5001);
    let socket = stack.create_socket(config.listen, 2).unwrap();
    let (sent, _) = send_file(
        config,
        "upload".parse().unwrap(),
        "stored".parse().unwrap(),
        options(block_size, window_size, None),
        |path| client_disk.open(path),
        socket,
        instant,
        TestRng,
    )
    .unwrap();
    assert_eq!(sent, length);
    assert_eq!(
        server_disk.contents("stored", <[u8]>::to_vec).unwrap(),
        data
    );
}

#[test]
fn round_trip_with_window_of_one() {
    round_trip(6901, 512, 1, 5000);
}

#[test]
fn round_trip_with_largest_window_and_block() {
    round_trip(
        6902,
        PREFERRED_DATA_BLOCK_SIZE,
        MAX_BLOCKS_FOR_MULTI_READER,
        FILE_CAPACITY,
    );
}

#[test]
fn round_trip_of_exact_block_multiple() {
    round_trip(6903, 512, 4, 2048);
}

#[test]
fn missing_file_is_reported() {
    let (server_link, client_link) = links();
    let server_disk: &'static RamDisk = leak(RamDisk::new());
    let client_disk: &'static RamDisk = leak(RamDisk::new());
    start_server(6904, server_link, server_disk);

    let stack = new_stack(client_link, CLIENT_MAC, 2);
    let mut config = client_config(6904, 5002);
    config.request_timeout = Duration::from_secs(1);
    let socket = stack.create_socket(config.listen, 1).unwrap();
    let result = receive_file(
        config,
        "local".parse().unwrap(),
        "absent".parse().unwrap(),
        options(512, 1, Some(0)),
        |path| client_disk.create(path, false),
        socket,
        instant,
        TestRng,
    );
    assert!(result.is_err());
}

#[test]
fn upload_of_exactly_one_slot_is_stored() {
    let port = 6905;
    let (server_link, client_link) = links();
    let server_disk: &'static RamDisk = leak(RamDisk::new());
    let client_disk: &'static RamDisk = leak(RamDisk::new());
    let data = sample(FILE_CAPACITY);
    assert!(client_disk.insert("upload", &data));
    start_server(port, server_link, server_disk);

    let stack = new_stack(client_link, CLIENT_MAC, 2);
    let config = client_config(port, 5003);
    let socket = stack.create_socket(config.listen, 1).unwrap();
    send_file(
        config,
        "upload".parse().unwrap(),
        "stored".parse().unwrap(),
        options(512, 1, None),
        |path| client_disk.open(path),
        socket,
        instant,
        TestRng,
    )
    .unwrap();
    assert_eq!(
        server_disk.contents("stored", <[u8]>::to_vec).unwrap(),
        data
    );
}

#[test]
fn storage_rejects_files_that_do_not_fit() {
    let disk: &'static RamDisk = leak(RamDisk::new());
    assert!(!disk.insert("too-big", &sample(FILE_CAPACITY + 1)));

    let mut writer = disk.create(&"file".parse().unwrap(), false).unwrap();
    assert_eq!(writer.write(&sample(FILE_CAPACITY)).unwrap(), FILE_CAPACITY);
    let error = writer.write(&[1]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::OutOfMemory);
    assert!(disk.create(&"file".parse().unwrap(), false).is_err());
}
