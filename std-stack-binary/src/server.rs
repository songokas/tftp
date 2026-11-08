use core::time::Duration;

use rand::rngs::OsRng;
use tftp_binary_common::time::instant_callback;
use tftp_dus::server::server;
use tftp_dus::server::ServerConfig;

use crate::cli::ServerArgs;
use crate::client::parse_file_path;
use crate::error::BinResult;
use crate::files::create_server_reader;
use crate::files::create_server_writer;
use crate::socket::create_bound_socket;
use crate::socket::create_socket;

pub fn start_server(args: &ServerArgs<'_>) -> BinResult<()> {
    let listen = args
        .listen
        .parse()
        .map_err(|_| "Listen must be an IP address with port")?;

    #[cfg(feature = "encryption")]
    let (private_key, authorized_keys) = {
        use crate::client::to_library_error;
        use tftp_binary_common::io::create_line_reader;
        use tftp_binary_common::keys::read_private_value_or_file;
        (
            args.private_key
                .map(read_private_value_or_file)
                .transpose()
                .map_err(to_library_error)?,
            args.authorized_keys
                .map(|path| {
                    tftp_dus::key_management::read_authorized_keys(create_line_reader(path)?)
                })
                .transpose()?,
        )
    };
    #[cfg(not(feature = "encryption"))]
    let (private_key, authorized_keys) = (None, None);

    let require_full_encryption = args
        .require_full_encryption
        .unwrap_or(cfg!(feature = "encryption") && args.authorized_keys.is_some());

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
    server(
        config,
        create_server_reader,
        create_server_writer,
        create_socket,
        create_bound_socket,
        instant_callback,
        OsRng,
    )?;
    Ok(())
}
