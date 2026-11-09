use core::net::SocketAddr;
use core::time::Duration;
use std::net::ToSocketAddrs;

use tftp_binary_common::client::connection_options;
use tftp_binary_common::keys::load_authorized_keys;
use tftp_binary_common::keys::load_encryption_key;
use tftp_binary_common::keys::load_private_key;
use tftp_binary_common::keys::load_remote_public_key;
use tftp_dus::client::ClientConfig;
use tftp_dus::config::ConnectionOptions;
use tftp_dus::error::BoxedError;
use tftp_dus::server::ServerConfig;
use tftp_dus::types::DefaultString;

use crate::cli::ClientCliConfig;
use crate::cli::ServerCliConfig;
use crate::error::BinError;
use crate::error::BinResult;

impl ClientCliConfig {
    pub fn connection_options(&self, file_size: Option<u64>) -> BinResult<ConnectionOptions> {
        Ok(connection_options(
            self.encryption.values().level,
            self.block_size,
            self.window_size,
            self.retry_timeout,
            file_size,
        )?)
    }

    pub fn try_into(self, listen: SocketAddr, prefer_seek: bool) -> BinResult<ClientConfig> {
        let to_error = |e: BoxedError| BinError::from(e.to_string());
        let encryption = self.encryption.values();
        let remote_public_key = load_remote_public_key(
            encryption.server_public_key,
            encryption.known_hosts.map(|path| path.as_str()),
            &self.endpoint,
        )
        .map_err(to_error)?;
        let private_key = load_private_key(encryption.private_key).map_err(to_error)?;
        let encryption_key = load_encryption_key(encryption.encryption_key).map_err(to_error)?;

        let endpoint_str = match self.endpoint.rsplit_once(':') {
            Some(_) => self.endpoint,
            None => {
                use core::fmt::Write;
                let mut end = DefaultString::new();
                write!(&mut end, "{}:{}", self.endpoint, 69)
                    .map_err(|e| BinError::from(e.to_string()))?;
                end
            }
        };
        let endpoint = endpoint_str
            .as_str()
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| BinError::from("Unable to resolve endpoint address"))?;

        Ok(ClientConfig {
            listen,
            endpoint,
            request_timeout: Duration::from_millis(self.request_timeout),
            max_file_size: self.max_file_size,
            private_key,
            remote_public_key,
            allow_server_port_change: self.allow_server_port_change,
            prefer_seek,
            encryption_key,
        })
    }
}

impl ServerCliConfig {
    pub fn try_into(self) -> BinResult<ServerConfig> {
        let listen = self
            .listen
            .as_str()
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| BinError::from("Unable to resolve listen address"))?;

        let to_error = |e: BoxedError| BinError::from(e.to_string());
        let encryption = self.encryption.values();
        let private_key = load_private_key(encryption.private_key).map_err(to_error)?;
        let authorized_keys = load_authorized_keys(encryption.authorized_keys).map_err(to_error)?;
        let require_full_encryption = encryption
            .require_full_encryption
            .unwrap_or(encryption.authorized_keys.is_some());
        let error_to_authorized_only = encryption
            .error_to_authorized_only
            .unwrap_or(require_full_encryption);

        let require_server_port_change = self.require_server_port_change.unwrap_or(false);
        #[cfg(target_family = "windows")]
        let require_server_port_change = if self.require_server_port_change.is_none() {
            true
        } else if !require_server_port_change {
            return Err(BinError::from(
                "Windows server does not support reusing ports. Pass require-server-port-change",
            ));
        } else {
            require_server_port_change
        };

        Ok(ServerConfig {
            listen,
            directory: self.directory,
            allow_overwrite: self.allow_overwrite,
            max_window_size: self.max_window_size as u16,
            request_timeout: Duration::from_millis(self.request_timeout),
            max_connections: self.max_connections as u16,
            max_file_size: self.max_file_size,
            max_block_size: self.max_block_size as u16,
            private_key,
            require_full_encryption,
            authorized_keys,
            require_server_port_change,
            #[cfg(feature = "seek")]
            prefer_seek: self.prefer_seek,
            #[cfg(not(feature = "seek"))]
            prefer_seek: false,
            directory_list: self.directory_list,
            max_directory_depth: self.max_directory_depth,
            error_to_authorized_only,
        })
    }
}
