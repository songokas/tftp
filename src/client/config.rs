use core::time::Duration;

use crate::encryption::EncryptionKey;
use crate::encryption::SigningKey;
use crate::encryption::VerifyingKey;
use core::net::SocketAddr;

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub endpoint: SocketAddr,
    pub request_timeout: Duration,
    pub max_file_size: u64,
    pub private_key: Option<SigningKey>,
    pub remote_public_key: Option<VerifyingKey>,
    pub allow_server_port_change: bool,
    pub prefer_seek: bool,
    pub encryption_key: Option<EncryptionKey>,
}
