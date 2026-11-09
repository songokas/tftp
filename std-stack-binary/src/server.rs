use core::time::Duration;

use rand::rngs::OsRng;
use tftp_binary_common::keys::load_authorized_keys;
use tftp_binary_common::keys::load_private_key;
use tftp_dus::features::ENCRYPTION_ENABLED;
use tftp_dus::server::server;
use tftp_dus::server::ServerConfig;

use crate::cli::ServerArgs;
use crate::client::parse_file_path;
use crate::error::BinResult;
use crate::files::create_server_reader;
use crate::files::create_server_writer;
use crate::socket::create_bound_socket;
use crate::socket::create_socket;
use crate::time::instant_callback;

/// Static because the worker threads run for the life of the process.
#[cfg(feature = "multi_thread")]
static WORKERS: tftp_binary_common::worker_pool::WorkerPool<
    tftp_dus::server::Job<
        crate::socket::UdpBoundSocket,
        OsRng,
        tftp_binary_common::io::File,
        tftp_binary_common::io::File,
    >,
> = tftp_binary_common::worker_pool::WorkerPool::new();

pub fn start_server(args: &ServerArgs<'_>) -> BinResult<()> {
    let listen = args
        .listen
        .parse()
        .map_err(|_| "Listen must be an IP address with port")?;

    let private_key = load_private_key(args.private_key)?;
    let authorized_keys = load_authorized_keys(args.authorized_keys)?;

    let require_full_encryption = args
        .require_full_encryption
        .unwrap_or(ENCRYPTION_ENABLED && args.authorized_keys.is_some());

    let config = ServerConfig {
        listen,
        directory: parse_file_path(args.directory)?,
        allow_overwrite: args.allow_overwrite,
        max_window_size: args.max_window_size as u16,
        request_timeout: Duration::from_millis(args.request_timeout),
        max_connections: args.max_connections as u16,
        max_file_size: args.max_file_size,
        max_block_size: args.max_block_size as u16,
        authorized_keys,
        private_key,
        require_full_encryption,
        require_server_port_change: args.require_server_port_change,
        prefer_seek: args.prefer_seek,
        directory_list: None,
        max_directory_depth: args.max_directory_depth as u16,
        error_to_authorized_only: args
            .error_to_authorized_only
            .unwrap_or(require_full_encryption),
    };

    #[cfg(feature = "multi_thread")]
    let spawner = WORKERS.start(args.max_connections as usize)?;
    server(
        config,
        create_server_reader,
        create_server_writer,
        create_socket,
        create_bound_socket,
        instant_callback,
        OsRng,
        #[cfg(feature = "multi_thread")]
        spawner,
    )?;
    Ok(())
}
