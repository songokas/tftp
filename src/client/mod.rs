mod config;
mod connection;
#[cfg(feature = "encryption")]
mod encryption_socket;
#[cfg(feature = "encryption")]
mod encryption_socket_builder;
#[cfg(not(feature = "encryption"))]
use crate::features::no_encryption_socket_builder as encryption_socket_builder;
pub(crate) mod extensions;
mod receiver;
mod sender;
#[cfg(feature = "encryption")]
mod session_encryption;
#[cfg(test)]
#[allow(dead_code)] // what is used depends on the feature set
pub(crate) mod test_support;
pub use config::ClientConfig;
pub use receiver::receive_file;
pub use sender::send_file;

#[cfg(not(feature = "encryption"))]
use crate::features::no_client_session_encryption as session_encryption;
