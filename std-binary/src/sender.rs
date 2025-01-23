use core::time::Duration;
use std::path::Path;

use log::*;
use rand::rngs::OsRng;
use tftp_dus::client::send_file;
use tftp_dus::config::ConnectionOptions;
#[cfg(not(feature = "encryption"))]
use tftp_dus::encryption::EncryptionLevel;
use tftp_dus::error::BoxedResult;
use tftp_dus::std_compat::io::Read;
use tftp_dus::std_compat::io::Seek;
use tftp_dus::types::FilePath;

use crate::cli::ClientCliConfig;
use crate::encryption_io::handle_hosts_file;
use crate::error::BinError;
use crate::error::BinResult;
use crate::io::instant_callback;
use crate::macros::cfg_encryption;
use crate::socket::*;

cfg_encryption! {
    use crate::encryption_io::create_encryption_reader;
}

pub fn start_send<CreateReader, R>(
    local_path: FilePath,
    remote_path: Option<FilePath>,
    config: ClientCliConfig,
    create_reader: CreateReader,
    prefer_seek: bool,
) -> BinResult<usize>
where
    R: Read + Seek,
    CreateReader: FnOnce(&FilePath) -> BoxedResult<(Option<u64>, R)>,
{
    let socket = create_socket(config.listen.as_str(), 1, false, 1)
        .map_err(|e| BinError::from(e.to_string()))?;
    // init_logger(socket.local_addr().expect("local address"));

    let options = ConnectionOptions {
        block_size: config.block_size as u16,
        retry_packet_after_timeout: Duration::from_millis(config.retry_timeout),
        file_size: None,
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

    let remote_path = match remote_path {
        Some(p) => p,
        None => Path::new(local_path.as_str())
            .file_name()
            .ok_or("Invalid local filename")?
            .to_string_lossy()
            .parse()
            .expect("Invalid local file name"),
    };
    let client_config = config.try_into(prefer_seek)?;
    let result = match client_config.encryption_key {
        #[cfg(feature = "encryption")]
        Some(key) => send_file(
            client_config,
            local_path,
            remote_path,
            options,
            create_encryption_reader(key, OsRng, create_reader),
            socket,
            instant_callback,
            OsRng,
        ),
        _ => send_file(
            client_config,
            local_path,
            remote_path,
            options,
            create_reader,
            socket,
            instant_callback,
            OsRng,
        ),
    };
    result
        .map(|(total, _remote_key)| {
            debug!("Client total sent {}", total);
            handle_hosts_file(known_hosts_file.as_deref(), _remote_key, &endpoint);
            total
        })
        .map_err(|e| BinError::from(e.to_string()))
}
