use core::time::Duration;

use crate::encryption::SigningKey;
use crate::key_management::AuthorizedKeys;
use crate::std_compat::net::SocketAddr;
use crate::types::FilePath;
use crate::types::ShortString;

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub directory: FilePath,
    pub allow_overwrite: bool,
    pub max_window_size: u16,
    pub request_timeout: Duration,
    pub max_connections: u16,
    pub max_file_size: u64,
    pub max_block_size: u16,
    pub authorized_keys: Option<AuthorizedKeys>,
    pub private_key: Option<SigningKey>,
    pub require_full_encryption: bool,
    pub require_server_port_change: bool,
    pub prefer_seek: bool,
    pub directory_list: Option<ShortString>,
    pub max_directory_depth: u16,
    pub error_to_authorized_only: bool,
}
