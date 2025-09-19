use core::net::SocketAddr;
use core::time::Duration;
use std::net::ToSocketAddrs;

use tftp_dus::client::ClientConfig;
use tftp_dus::server::ServerConfig;
use tftp_dus::types::DefaultString;

use crate::cli::ClientCliConfig;
use crate::cli::ServerCliConfig;
use crate::error::BinError;
use crate::error::BinResult;
use crate::macros::cfg_encryption;

cfg_encryption! {
    use tftp_dus::encryption::*;
    use tftp_dus::key_management::*;
    use crate::io::create_buff_reader;
}

impl ClientCliConfig {
    pub fn try_into(self, listen: SocketAddr, prefer_seek: bool) -> BinResult<ClientConfig> {
        #[cfg(feature = "encryption")]
        let remote_public_key = match (&self.server_public_key, &self.known_hosts) {
            (Some(p), _) => decode_verifying_key(p.as_bytes())
                .map_err(|e| BinError::from(e.to_string()))?
                .into(),
            (_, Some(p)) => get_from_known_hosts(
                create_buff_reader(p.as_str()).map_err(|e| BinError::from(e.to_string()))?,
                &self.endpoint,
            )
            .map_err(|e| BinError::from(e.to_string()))?,
            _ => None,
        };
        #[cfg(not(feature = "encryption"))]
        let remote_public_key = None;

        #[cfg(feature = "encryption")]
        let private_key = self
            .private_key
            .as_deref()
            .map(crate::encryption_io::read_private_value_or_file)
            .transpose()
            .map_err(|e| BinError::from(e.to_string()))?;
        #[cfg(not(feature = "encryption"))]
        let private_key = None;

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

        #[cfg(feature = "encryption")]
        let encryption_key: Option<EncryptionKey> = self
            .encryption_key
            .as_deref()
            .map(crate::encryption_io::read_private_value_or_file)
            .transpose()
            .map_err(|e| BinError::from(e.to_string()))?
            .map(|s| s.to_bytes());

        #[cfg(not(feature = "encryption"))]
        let encryption_key = None;

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

        #[cfg(feature = "encryption")]
        let require_full_encryption = self
            .require_full_encryption
            .unwrap_or(self.authorized_keys.is_some());
        #[cfg(not(feature = "encryption"))]
        let require_full_encryption = false;

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
            #[cfg(feature = "encryption")]
            private_key: self
                .private_key
                .as_deref()
                .map(crate::encryption_io::read_private_value_or_file)
                .transpose()
                .map_err(|e| BinError::from(e.to_string()))?,
            #[cfg(not(feature = "encryption"))]
            private_key: None,
            require_full_encryption,
            #[cfg(feature = "encryption")]
            authorized_keys: self
                .authorized_keys
                .map(|p| read_authorized_keys(create_buff_reader(p.as_str())?))
                .transpose()
                .map_err(|e| BinError::from(e.to_string()))?,
            #[cfg(not(feature = "encryption"))]
            authorized_keys: None,
            require_server_port_change,
            #[cfg(feature = "seek")]
            prefer_seek: self.prefer_seek,
            #[cfg(not(feature = "seek"))]
            prefer_seek: false,
            directory_list: self.directory_list,
            max_directory_depth: self.max_directory_depth,
            #[cfg(feature = "encryption")]
            error_to_authorized_only: self
                .error_to_authorized_only
                .unwrap_or(require_full_encryption),
            #[cfg(not(feature = "encryption"))]
            error_to_authorized_only: false,
        })
    }
}
