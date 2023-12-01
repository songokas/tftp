use core::time::Duration;
use std::path::Path;

use log::*;
use rand::rngs::OsRng;
use tftp::client::receive_file;
use tftp::config::ConnectionOptions;
#[cfg(not(feature = "encryption"))]
use tftp::encryption::EncryptionLevel;
use tftp::error::BoxedResult;
use tftp::std_compat::io::Write;
use tftp::types::FilePath;

use crate::cli::BinError;
use crate::cli::BinResult;
use crate::cli::ClientCliConfig;
use crate::io::handle_hosts_file;
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
    CreateWriter: Fn(&FilePath) -> BoxedResult<W>,
{
    let socket =
        create_socket(&config.listen, 1, false).map_err(|e| BinError::from(e.to_string()))?;
    // init_logger(socket.local_addr().expect("local address"));

    let options = ConnectionOptions {
        block_size: config.block_size as u16,
        retry_packet_after_timeout: Duration::from_millis(config.retry_timeout),
        file_size: Some(0),
        encryption_keys: None,
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
    receive_file(
        config.try_into(false, false)?,
        local_path,
        remote_path,
        options,
        create_writer,
        socket,
        instant_callback,
        OsRng,
    )
    .map(|(total, _remote_key)| {
        debug!("Client total received {}", total);
        let file = known_hosts_file.as_deref();
        handle_hosts_file(file, _remote_key, &endpoint);
        total
    })
    .map_err(|e| BinError::from(e.to_string()))
}
