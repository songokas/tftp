use log::*;
use rand::rngs::OsRng;
#[cfg(feature = "encryption")]
use tftp_binary_common::keys::create_encryption_writer;
use tftp_binary_common::keys::handle_hosts_file;
use tftp_binary_common::path::file_name;
use tftp_dus::client::receive_file;
use tftp_dus::error::BoxedResult;
use tftp_dus::std_compat::io::Write;
use tftp_dus::types::FilePath;

use crate::cli::ClientCliConfig;
use crate::error::BinError;
use crate::error::BinResult;
use crate::socket::*;
use crate::time::instant_callback;

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

    let options = config.connection_options(Some(0))?;
    let known_hosts_file = config.encryption.values().known_hosts.cloned();
    let endpoint = config.endpoint.clone();

    let local_path = match local_path {
        Some(p) => p,
        None => file_name(&remote_path)?,
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
