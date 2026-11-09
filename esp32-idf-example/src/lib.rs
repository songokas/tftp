//! The chip independent part of the example, which also runs on a PC.

pub mod net;
pub mod storage;

use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use rand::rngs::OsRng;
use tftp_dus::error::DefaultBoxedResult;
use tftp_dus::server::server;
use tftp_dus::server::ServerConfig;
use tftp_dus::server::ThreadSpawner;

/// Each connection needs a thread stack, so this is limited by free RAM.
pub const MAX_CONNECTIONS: u16 = 4;
pub const MAX_WINDOW_SIZE: u16 = 4;
pub const MAX_BLOCK_SIZE: u16 = 1024;
pub const MAX_FILE_SIZE: u64 = 1024 * 1024;

pub fn server_config(listen: SocketAddr, directory: &str) -> ServerConfig {
    ServerConfig {
        listen,
        directory: directory.into(),
        allow_overwrite: true,
        max_window_size: MAX_WINDOW_SIZE,
        request_timeout: Duration::from_secs(15),
        max_connections: MAX_CONNECTIONS,
        max_file_size: MAX_FILE_SIZE,
        max_block_size: MAX_BLOCK_SIZE,
        authorized_keys: None,
        private_key: None,
        require_full_encryption: false,
        // lwIP can not share the listening port between sockets
        require_server_port_change: true,
        prefer_seek: false,
        directory_list: None,
        max_directory_depth: 0,
        error_to_authorized_only: false,
    }
}

/// Runs the server on the calling thread.
pub fn serve(config: ServerConfig) -> DefaultBoxedResult {
    server(
        config,
        storage::open_reader,
        storage::open_writer,
        |listen, socket_id, _reuse, _capacity| net::create_socket(listen, socket_id),
        net::create_bound_socket,
        Instant::now,
        OsRng,
        ThreadSpawner,
    )
}
