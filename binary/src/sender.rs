use core::time::Duration;
use std::path::Path;

use crate::cli::ClientCliConfig;
use log::*;
use rand::rngs::OsRng;
use tftp::client::send_file;
use tftp::config::ConnectionOptions;
use tftp::error::BoxedResult;

use tftp::std_compat::io::Read;
use tftp::std_compat::io::Seek;
use tftp::types::FilePath;

use crate::cli::BinError;
use crate::cli::BinResult;

use crate::io::handle_hosts_file;
use crate::io::instant_callback;

#[cfg(not(feature = "encryption"))]
use tftp::encryption::EncryptionLevel;

use crate::socket::*;

pub fn start_send<CreateReader, R>(
    local_path: FilePath,
    remote_path: Option<FilePath>,
    config: ClientCliConfig,
    create_reader: CreateReader,
    ignore_rate_control: bool,
    prefer_seek: bool,
) -> BinResult<usize>
where
    R: Read + Seek,
    CreateReader: Fn(&FilePath) -> BoxedResult<(Option<u64>, R)>,
{
    let socket = create_socket(config.listen.as_str(), 1, false)
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
    send_file(
        config.try_into(ignore_rate_control, prefer_seek)?,
        local_path,
        remote_path,
        options,
        create_reader,
        socket,
        instant_callback,
        OsRng,
    )
    .map(|(total, _remote_key)| {
        debug!("Client total sent {}", total);
        let file = known_hosts_file.as_deref();
        handle_hosts_file(file, _remote_key, &endpoint);
        total
    })
    .map_err(|e| BinError::from(e.to_string()))
}
