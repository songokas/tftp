use core::time::Duration;

use crate::encryption::EncryptionKey;
use crate::encryption::PrivateKey;
use crate::encryption::PublicKey;
use crate::std_compat::net::SocketAddr;
use crate::types::DefaultString;

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: DefaultString,
    pub endpoint: SocketAddr,
    pub request_timeout: Duration,
    pub max_file_size: u64,
    pub private_key: Option<PrivateKey>,
    pub remote_public_key: Option<PublicKey>,
    pub allow_server_port_change: bool,
    pub prefer_seek: bool,
    pub encryption_key: Option<EncryptionKey>,
}
