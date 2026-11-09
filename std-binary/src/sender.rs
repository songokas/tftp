use log::*;
use rand::rngs::OsRng;
#[cfg(feature = "encryption")]
use tftp_binary_common::keys::create_encryption_reader;
use tftp_binary_common::keys::handle_hosts_file;
use tftp_binary_common::path::file_name;
use tftp_dus::client::send_file;
use tftp_dus::error::BoxedResult;
use tftp_dus::std_compat::io::Read;
use tftp_dus::std_compat::io::Seek;
use tftp_dus::types::FilePath;

use crate::cli::ClientCliConfig;
use crate::error::BinError;
use crate::error::BinResult;
use crate::socket::*;
use crate::time::instant_callback;

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
    let listen = if let Some(l) = &config.listen {
        obtain_listen_socket(l).map_err(|e| BinError::from(e.to_string()))?
    } else {
        obtain_listen_socket_based_on_endpoint(&config.endpoint)
            .map_err(|e| BinError::from(e.to_string()))?
    };
    let socket = create_socket(listen, 1, false, 1).map_err(|e| BinError::from(e.to_string()))?;
    // init_logger(socket.local_addr().expect("local address"));
    //
    let options = config.connection_options(None)?;
    let known_hosts_file = config.encryption.values().known_hosts.cloned();
    let endpoint = config.endpoint.clone();

    let remote_path = match remote_path {
        Some(p) => p,
        None => file_name(&local_path)?,
    };
    let client_config = config.try_into(listen, prefer_seek)?;
    let result = match client_config.encryption_key {
        #[cfg(feature = "encryption")]
        Some(key) => {
            let block_size = options.block_size_with_encryption();
            send_file(
                client_config,
                local_path,
                remote_path,
                options,
                create_encryption_reader(key, OsRng, block_size, create_reader),
                socket,
                instant_callback,
                OsRng,
            )
        }
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
