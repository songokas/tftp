use core::time::Duration;
use std::path::Path;

use log::*;
use rand::rngs::OsRng;
use tftp_dus::client::receive_file;
use tftp_dus::config::ConnectionOptions;
#[cfg(not(feature = "encryption"))]
use tftp_dus::encryption::EncryptionLevel;
use tftp_dus::error::BoxedResult;
use tftp_dus::std_compat::io::Write;
use tftp_dus::types::FilePath;

use crate::cli::ClientCliConfig;
#[cfg(feature = "encryption")]
use crate::encryption_io::create_encryption_writer;
use crate::encryption_io::handle_hosts_file;
use crate::error::BinError;
use crate::error::BinResult;
use crate::io::instant_callback;
use crate::socket::*;

pub fn start_receive<CreateWriter, W>(
    local_path: Option<FilePath>,
    remote_path: FilePath,
    config: ClientCliConfig,
    create_writer: CreateWriter,
) -> BinResult<usize>
where
    W: Write,
    CreateWriter: FnOnce(&FilePath) -> BoxedResult<W>,
{
    let listen = if let Some(l) = &config.listen {
        obtain_listen_socket(l).map_err(|e| BinError::from(e.to_string()))?
    } else {
        obtain_listen_socket_based_on_endpoint(&config.endpoint)
            .map_err(|e| BinError::from(e.to_string()))?
    };
    let socket = create_socket(listen, 1, false, 1).map_err(|e| BinError::from(e.to_string()))?;
    // init_logger(socket.local_addr().expect("local address"));

    let options = ConnectionOptions {
        block_size: config.block_size as u16,
        retry_packet_after_timeout: Duration::from_millis(config.retry_timeout),
        file_size: Some(0),
        #[cfg(feature = "encryption")]
        encryption_level: config
            .encryption_level
            .parse()
            .map_err(|_| BinError::from("Invalid encryption level specified"))?,

        #[cfg(not(feature = "encryption"))]
        encryption_level: EncryptionLevel::None,
        window_size: config.window_size as u16,
    };
    #[cfg(feature = "encryption")]
    let known_hosts_file = config.known_hosts.clone();
    #[cfg(not(feature = "encryption"))]
    let known_hosts_file: Option<FilePath> = None;
    let endpoint = config.endpoint.clone();

    let local_path = match local_path {
        Some(p) => p,
        None => Path::new(remote_path.as_str())
            .file_name()
            .ok_or("Invalid remote file name")?
            .to_string_lossy()
            .parse()
            .expect("Invalid remote file name"),
    };
    let client_config = config.try_into(listen, false)?;
    let result = match client_config.encryption_key {
        #[cfg(feature = "encryption")]
        Some(key) => receive_file(
            client_config,
            local_path,
            remote_path,
            options,
            create_encryption_writer(key, create_writer),
            socket,
            instant_callback,
            OsRng,
        ),
        _ => receive_file(
            client_config,
            local_path,
            remote_path,
            options,
            create_writer,
            socket,
            instant_callback,
            OsRng,
        ),
    };

    result
        .map(|(total, _remote_key)| {
            debug!("Client total received {}", total);
            handle_hosts_file(known_hosts_file.as_deref(), _remote_key, &endpoint);
            total
        })
        .map_err(|e| BinError::from(e.to_string()))
}
