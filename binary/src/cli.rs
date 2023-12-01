use core::time::Duration;
use std::net::ToSocketAddrs;

use clap::Parser;
use clap::Subcommand;
use tftp::client::ClientConfig;
use tftp::config::DEFAULT_RETRY_PACKET_TIMEOUT;
use tftp::config::DEFAULT_WINDOW_SIZE;
use tftp::config::EXTENSION_BLOCK_SIZE_MIN;
use tftp::config::EXTENSION_TIMEOUT_SIZE_MAX;
use tftp::config::EXTENSION_TIMEOUT_SIZE_MIN;
use tftp::config::EXTENSION_WINDOW_SIZE_MIN;
use tftp::config::MAX_BLOCKS_READER;
use tftp::config::MAX_CLIENTS;
use tftp::config::MAX_DATA_BLOCK_SIZE;
use tftp::server::ServerConfig;
use tftp::types::DefaultString;
use tftp::types::FilePath;

use crate::macros::cfg_encryption;

cfg_encryption! {
    use tftp::encryption::*;
    use tftp::key_management::*;
    use tftp::types::ShortString;
    use crate::io::create_buff_reader;
}

pub type BinError = Box<dyn std::error::Error + Sync + Send>;
pub type BinResult<T> = Result<T, BinError>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(short, long, default_value = "info")]
    pub verbosity: DefaultString,
}

#[derive(Parser, Debug, Clone)]
pub struct ClientCliConfig {
    pub endpoint: DefaultString,

    #[arg(short, long, default_value = "0.0.0.0:0")]
    pub listen: DefaultString,

    #[arg(
        long,
        default_value_t = 15000,
        help = "Request time out in milliseconds"
    )]
    pub request_timeout: u64,

    #[arg(long, default_value_t = MAX_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(MAX_DATA_BLOCK_SIZE as u64)))]
    pub block_size: u64,

    #[arg(long, default_value_t = DEFAULT_WINDOW_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_WINDOW_SIZE_MIN as u64)..=(MAX_BLOCKS_READER as u64)))]
    pub window_size: u64,

    #[arg(
        long,
        default_value_t = DEFAULT_RETRY_PACKET_TIMEOUT.as_millis() as u64,
        value_parser = clap::value_parser!(u64).range((EXTENSION_TIMEOUT_SIZE_MIN as u64)..(EXTENSION_TIMEOUT_SIZE_MAX as u64)),
        help = "Resend packet after timeout in ms"
    )]
    pub retry_timeout: u64,

    #[arg(long, default_value_t = 10485760, help = "Max file size to receive")]
    pub max_file_size: u64,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        default_value = "optional-protocol",
        help = "Available values protocol, data, optional-data, optional-protocol, none"
    )]
    pub encryption_level: ShortString,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Private key to use: value or FILE")]
    pub private_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Remote server public key to use for encryption")]
    pub server_public_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(
        long,
        help = "Path to a known hosts file where server public key will be retrieved. Format: endpoint public key per line"
    )]
    pub known_hosts: Option<FilePath>,

    #[arg(long)]
    pub allow_server_port_change: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ServerCliConfig {
    pub listen: DefaultString,

    pub directory: FilePath,

    #[arg(short, long)]
    pub allow_overwrite: bool,

    #[arg(long, default_value_t = MAX_CLIENTS as u64, value_parser = clap::value_parser!(u64).range(1..=(MAX_CLIENTS as u64)))]
    pub max_connections: u64,

    #[arg(long, default_value_t = MAX_BLOCKS_READER as u64, value_parser = clap::value_parser!(u64).range(1..=(MAX_BLOCKS_READER) as u64))]
    pub max_window_size: u64,

    #[arg(
        long,
        default_value_t = 15000,
        help = "Request time out in milliseconds"
    )]
    pub request_timeout: u16,

    #[arg(
        long,
        default_value_t = 104857600,
        help = "Max file size to receive in bytes"
    )]
    pub max_file_size: u64,

    #[arg(long, default_value_t = MAX_DATA_BLOCK_SIZE as u64, value_parser = clap::value_parser!(u64).range((EXTENSION_BLOCK_SIZE_MIN as u64)..=(MAX_DATA_BLOCK_SIZE as u64)))]
    pub max_block_size: u64,

    #[cfg(feature = "encryption")]
    #[arg(long)]
    pub authorized_keys: Option<FilePath>,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Private key to use: value or FILE")]
    pub private_key: Option<ShortString>,

    #[cfg(feature = "encryption")]
    #[arg(long, help = "Require that connection be fully encrypted")]
    pub required_full_encryption: Option<bool>,

    #[arg(long)]
    pub require_server_port_change: bool,

    #[cfg(feature = "seek")]
    #[arg(long)]
    prefer_seek: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Send {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(value_name = "FILE")]
        local_path: FilePath,

        #[arg(short, long)]
        remote_path: Option<FilePath>,

        #[arg(long)]
        ignore_rate_control: bool,

        #[cfg(feature = "seek")]
        #[arg(long)]
        prefer_seek: bool,
    },
    #[cfg(feature = "sync")]
    Sync {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(
            long,
            default_value_t = 1000,
            help = "Block duration when reading the file in milliseconds"
        )]
        block_duration: u64,

        #[arg(long)]
        ignore_rate_control: bool,

        #[arg(value_name = "DIRECTORY")]
        dir_path: Option<FilePath>,
    },

    Receive {
        #[clap(flatten)]
        config: ClientCliConfig,

        #[arg(long)]
        local_path: Option<FilePath>,

        #[arg(value_name = "FILE")]
        remote_path: FilePath,
    },

    Server(ServerCliConfig),
}

impl ClientCliConfig {
    pub fn try_into(self, ignore_rate_control: bool, prefer_seek: bool) -> BinResult<ClientConfig> {
        #[cfg(feature = "encryption")]
        let remote_public_key = match (&self.server_public_key, &self.known_hosts) {
            (Some(p), _) => decode_public_key(p.as_bytes())
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
            .map(crate::io::read_private_value_or_file)
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
        #[cfg(not(feature = "std"))]
        let endpoint = crate::socket::std_to_socket_addr(endpoint);
        Ok(ClientConfig {
            listen: self.listen,
            endpoint,
            request_timeout: Duration::from_millis(self.request_timeout),
            max_file_size: self.max_file_size,
            private_key,
            remote_public_key,
            allow_server_port_change: self.allow_server_port_change,
            ignore_rate_control,
            prefer_seek,
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
        #[cfg(not(feature = "std"))]
        let listen = crate::socket::std_to_socket_addr(listen);
        Ok(ServerConfig {
            listen,
            directory: self.directory,
            allow_overwrite: self.allow_overwrite,
            max_window_size: self.max_window_size as u16,
            request_timeout: Duration::from_millis(self.request_timeout as u64),
            max_connections: self.max_connections as u16,
            max_file_size: self.max_file_size,
            max_block_size: self.max_block_size as u16,
            #[cfg(feature = "encryption")]
            private_key: self
                .private_key
                .as_deref()
                .map(crate::io::read_private_value_or_file)
                .transpose()
                .map_err(|e| BinError::from(e.to_string()))?,
            #[cfg(not(feature = "encryption"))]
            private_key: None,
            #[cfg(feature = "encryption")]
            required_full_encryption: self
                .required_full_encryption
                .unwrap_or(self.authorized_keys.is_some()),
            #[cfg(not(feature = "encryption"))]
            required_full_encryption: false,
            #[cfg(feature = "encryption")]
            authorized_keys: self
                .authorized_keys
                .map(|p| read_authorized_keys(create_buff_reader(p.as_str())?))
                .transpose()
                .map_err(|e| BinError::from(e.to_string()))?,
            #[cfg(not(feature = "encryption"))]
            authorized_keys: None,
            require_server_port_change: self.require_server_port_change,
            #[cfg(feature = "seek")]
            prefer_seek: self.prefer_seek,
            #[cfg(not(feature = "seek"))]
            prefer_seek: false,
        })
    }
}
